"""
core/onboarding.py

Pre-start environment analysis.
Runs once when the database is empty (first boot).
Displays a full-screen briefing in the browser before the dashboard loads.

Shows:
  - OS, CPU, RAM, GPU detection
  - Which services are running (Docker, Wazuh, Ollama)
  - What the system will monitor
  - Recommended model based on available RAM
  - Estimated resource usage
"""

import asyncio
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

from core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class OnboardingReport:
    # Hardware
    os_name:        str
    cpu_cores:      int
    ram_gb:         int
    gpu_info:       str

    # Services detected
    docker_running: bool
    wazuh_running:  bool
    ollama_running: bool
    ollama_models:  list[str]
    ssh_exposed:    bool
    open_ports:     list[int]

    # Recommendations
    recommended_model:      str
    fallback_model:         str
    estimated_ram_usage_gb: float
    ram_sufficient:         bool
    warnings:               list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "os_name":              self.os_name,
            "cpu_cores":            self.cpu_cores,
            "ram_gb":               self.ram_gb,
            "gpu_info":             self.gpu_info,
            "docker_running":       self.docker_running,
            "wazuh_running":        self.wazuh_running,
            "ollama_running":       self.ollama_running,
            "ollama_models":        self.ollama_models,
            "ssh_exposed":          self.ssh_exposed,
            "open_ports":           self.open_ports,
            "recommended_model":    self.recommended_model,
            "fallback_model":       self.fallback_model,
            "estimated_ram_gb":     self.estimated_ram_usage_gb,
            "ram_sufficient":       self.ram_sufficient,
            "warnings":             self.warnings,
        }


async def run_onboarding() -> OnboardingReport:
    """
    Analyze the environment and return a full briefing report.
    Called from main.py lifespan on first boot.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _collect)


def _collect() -> OnboardingReport:
    warnings = []

    # ── Hardware ─────────────────────────────────────────────────────────
    os_name   = f"{platform.system()} {platform.release()}"
    try:
        import distro
        os_name = distro.name(pretty=True)
    except ImportError:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass

    cpu_cores = psutil.cpu_count(logical=True) or 1
    ram_gb    = int(psutil.virtual_memory().total / 1e9)
    gpu_info  = _detect_gpu()

    # ── Services ─────────────────────────────────────────────────────────
    docker_running = _check_docker()
    wazuh_running  = _check_wazuh()
    ollama_running, ollama_models = _check_ollama()
    ssh_exposed    = _check_ssh()
    open_ports     = _get_open_ports()

    # ── Model recommendation ──────────────────────────────────────────────
    # Rule: leave 4GB for OS + Wazuh + app overhead
    model_budget_gb = ram_gb - 4
    recommended, fallback = _recommend_model(model_budget_gb, gpu_info)

    # Estimated usage: app(0.5) + wazuh(2.0) + model
    model_size = {"qwen2.5:7b": 4.5, "qwen2.5:14b": 9.0,
                  "llama3.1:8b": 5.0, "gemma3:4b": 3.0}.get(recommended, 5.0)
    estimated  = 0.5 + 2.0 + model_size
    sufficient = ram_gb >= estimated + 2

    # ── Warnings ──────────────────────────────────────────────────────────
    if ram_gb < 8:
        warnings.append(f"Only {ram_gb}GB RAM — system may be slow. 16GB+ recommended.")
    if not docker_running:
        warnings.append("Docker is not running. Container monitoring will be unavailable.")
    if not wazuh_running:
        warnings.append("Wazuh is not running. Security alerts will not be available.")
    if not ollama_running:
        warnings.append(f"Ollama is not running. Start it with: ollama serve")
    if ollama_running and not ollama_models:
        warnings.append(f"No models loaded. Pull one with: ollama pull {recommended}")
    if ssh_exposed:
        warnings.append("SSH port 22 is exposed. Wazuh will monitor for brute force attempts.")
    if not sufficient:
        warnings.append(
            f"RAM may be insufficient for {recommended} + Wazuh. "
            f"Consider {fallback} instead."
        )

    return OnboardingReport(
        os_name             = os_name,
        cpu_cores           = cpu_cores,
        ram_gb              = ram_gb,
        gpu_info            = gpu_info,
        docker_running      = docker_running,
        wazuh_running       = wazuh_running,
        ollama_running      = ollama_running,
        ollama_models       = ollama_models,
        ssh_exposed         = ssh_exposed,
        open_ports          = open_ports,
        recommended_model   = recommended,
        fallback_model      = fallback,
        estimated_ram_usage_gb = round(estimated, 1),
        ram_sufficient      = sufficient,
        warnings            = warnings,
    )


def _detect_gpu() -> str:
    # NVIDIA
    try:
        import subprocess
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=3,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().splitlines()[0]
    except Exception:
        pass
    # AMD
    try:
        r = subprocess.run(["rocm-smi", "--showproductname"],
                          capture_output=True, text=True, timeout=3)
        if r.returncode == 0:
            return "AMD GPU (ROCm)"
    except Exception:
        pass
    return "None detected (CPU inference)"


def _check_docker() -> bool:
    return Path("/var/run/docker.sock").exists()


def _check_wazuh() -> bool:
    wazuh_paths = [
        Path("/var/ossec/logs/alerts/alerts.json"),
        Path("/var/ossec/bin/wazuh-control"),
    ]
    return any(p.exists() for p in wazuh_paths)


def _check_ollama() -> tuple[bool, list[str]]:
    try:
        import httpx
        r = httpx.get(f"{settings.ollama_url}/api/tags", timeout=3.0)
        if r.status_code == 200:
            models = [m.get("name","") for m in r.json().get("models",[])]
            return True, [m for m in models if m]
        return True, []
    except Exception:
        return False, []


def _check_ssh() -> bool:
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr.port == 22:
                return True
    except Exception:
        pass
    return False


def _get_open_ports() -> list[int]:
    try:
        return sorted({
            conn.laddr.port
            for conn in psutil.net_connections(kind="inet")
            if conn.status == "LISTEN" and conn.laddr.port < 10000
        })
    except Exception:
        return []


def _recommend_model(budget_gb: float, gpu: str) -> tuple[str, str]:
    """Choose the best model for available memory."""
    has_gpu = "None" not in gpu

    if budget_gb >= 10 or (has_gpu and budget_gb >= 8):
        return "qwen2.5:14b", "qwen2.5:7b"
    if budget_gb >= 5:
        return "qwen2.5:7b", "llama3.1:8b"
    if budget_gb >= 4:
        return "llama3.1:8b", "gemma3:4b"
    return "gemma3:4b", "gemma3:4b"
