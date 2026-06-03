"""
pipeline/extractor.py

Stage 3: Entity Extraction.

Parses every event and pulls out the normalized actors:
  IPs, usernames, file paths, container names, processes,
  ports, file hashes, CVEs.

These entities are stored in event_entities for fast correlation queries.
The safety-net raw-scan at the end catches anything missed by specific field parsing.
"""

import re
import json
import logging
from typing import Optional

from core.models import Event, Entities, EventType

logger = logging.getLogger(__name__)

# ── Regex patterns ────────────────────────────────────────────────────────────
IP_PATTERN  = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
SHA256_PAT  = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_PAT     = re.compile(r'\b[a-fA-F0-9]{32}\b')

# IPs that are always noise — never worth correlating
NOISE_IPS = frozenset({
    "127.0.0.1", "0.0.0.0", "::1", "255.255.255.255",
    "localhost", "169.254.0.0",
})

# Usernames too generic to be useful for correlation
NOISE_USERS = frozenset({
    "root", "system", "daemon", "nobody",
    # Don't filter root in auth events — SSH brute forcing root is signal
})


class EntityExtractor:
    """
    Extracts normalized entities from any Event.
    Populates event.entities in place.
    """

    def extract(self, event: Event) -> Entities:
        """Extract entities from an event and return populated Entities object."""
        ips:        set[str] = set()
        users:      set[str] = set()
        files:      set[str] = set()
        containers: set[str] = set()
        processes:  set[str] = set()
        ports:      set[int] = set()
        hashes:     set[str] = set()
        cves:       set[str] = set()

        # ── Source-specific extraction ────────────────────────────────────────
        if event.wazuh:
            self._extract_wazuh(
                event.raw, ips, users, files,
                processes, ports, hashes, cves
            )
        elif event.docker:
            self._extract_docker(event.docker, containers, ips)
        elif event.system:
            self._extract_system(event.system, processes, ports)

        # ── Safety net: scan entire raw JSON ──────────────────────────────────
        # Catches IPs and CVEs in fields we didn't know to look at.
        # Protects against Wazuh schema changes and new rule packs.
        raw_str = json.dumps(event.raw)
        self._scan_raw(raw_str, ips, cves, hashes)

        # ── Clean and return ──────────────────────────────────────────────────
        return Entities(
            ips        = list(ips - NOISE_IPS),
            users      = [u for u in users if u and len(u) < 64],
            files      = list(files),
            containers = list(containers),
            processes  = list(processes),
            ports      = sorted(ports),
            hashes     = list(hashes),
            cves       = list(cves),
        )

    # ── Wazuh-specific extraction ─────────────────────────────────────────────

    def _extract_wazuh(
        self, raw: dict,
        ips: set, users: set, files: set,
        processes: set, ports: set, hashes: set, cves: set,
    ) -> None:
        data = raw.get("data", {})

        # ── IP addresses ──────────────────────────────────────────────────────
        # Wazuh uses many different field names for IPs across versions
        ip_fields = (
            "srcip", "src_ip", "dstip", "dst_ip",
            "remote_ip", "remoteip", "system_name",
        )
        for field in ip_fields:
            val = data.get(field)
            if val and isinstance(val, str):
                # May be "host (1.2.3.4)" format
                found = IP_PATTERN.findall(val)
                ips.update(found)
                # Also try the value itself if it's a bare IP
                if IP_PATTERN.match(val.strip()):
                    ips.add(val.strip())

        # ── Usernames ─────────────────────────────────────────────────────────
        user_fields = ("srcuser", "dstuser", "user", "username", "login")
        for field in user_fields:
            val = data.get(field)
            if val and isinstance(val, str) and len(val) < 64:
                users.add(val.lower().strip())

        # ── File paths (FIM / syscheck events) ───────────────────────────────
        # Wazuh stores syscheck under data.syscheck (not top-level raw.syscheck)
        syscheck = data.get("syscheck", {}) or raw.get("syscheck", {})
        if syscheck:
            path = syscheck.get("path")
            if path:
                files.add(path)
            # File hashes
            for hash_field in ("sha256_after", "sha256_before", "md5_after", "md5_before"):
                h = syscheck.get(hash_field)
                if h:
                    hashes.add(h)

        # Also check data.path for non-FIM file references
        for path_field in ("path", "file", "filename"):
            val = data.get(path_field)
            if val and isinstance(val, str) and val.startswith("/"):
                files.add(val)

        # ── Ports ─────────────────────────────────────────────────────────────
        port_fields = ("dstport", "dst_port", "sport", "src_port", "port")
        for field in port_fields:
            val = data.get(field)
            if val:
                try:
                    p = int(val)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except (ValueError, TypeError):
                    pass

        # ── CVEs from vulnerability detector ──────────────────────────────────
        vuln = data.get("vulnerability", {})
        if vuln.get("cve"):
            cves.add(vuln["cve"].upper())

        # ── Process names ─────────────────────────────────────────────────────
        for proc_field in ("process", "command", "program"):
            val = data.get(proc_field)
            if val and isinstance(val, str):
                # Extract just the executable name (not full path + args)
                exe = val.split()[0].split("/")[-1]
                if exe:
                    processes.add(exe)

    # ── Docker-specific extraction ────────────────────────────────────────────

    def _extract_docker(self, payload, containers: set, ips: set) -> None:
        containers.add(payload.container_name)
        # Container name without leading slash
        clean = payload.container_name.lstrip("/")
        if clean:
            containers.add(clean)

    # ── System event extraction ───────────────────────────────────────────────

    def _extract_system(self, payload, processes: set, ports: set) -> None:
        if payload.process_name:
            processes.add(payload.process_name)
        if payload.metric == "new_listening_port":
            try:
                p = int(payload.value)
                if 1 <= p <= 65535:
                    ports.add(p)
            except (ValueError, TypeError):
                pass

    # ── Safety net raw scan ───────────────────────────────────────────────────

    def _scan_raw(
        self, raw_str: str,
        ips: set, cves: set, hashes: set,
    ) -> None:
        """
        Scan the full raw event string for any IPs, CVEs, or hashes we missed.
        This handles Wazuh schema drift and unusual rule formats.
        """
        found_ips = IP_PATTERN.findall(raw_str)
        ips.update(found_ips)

        found_cves = CVE_PATTERN.findall(raw_str)
        cves.update(c.upper() for c in found_cves)

        # SHA-256 hashes (64 hex chars)
        found_sha256 = SHA256_PAT.findall(raw_str)
        hashes.update(found_sha256)
