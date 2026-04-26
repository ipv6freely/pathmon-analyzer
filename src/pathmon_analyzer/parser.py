"""Parser for MTR and httpstat log output."""

import re
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class MtrHop:
    """Represents a single hop in an MTR trace."""

    hop_number: int
    host: str
    loss_percent: float = 0.0
    sent: int = 0
    last_ms: float = 0.0
    avg_ms: float = 0.0
    best_ms: float = 0.0
    worst_ms: float = 0.0
    stdev_ms: float = 0.0
    asn: str = ""

    @property
    def is_problematic(self) -> bool:
        """Check if this hop shows signs of issues."""
        return self.loss_percent > 0 or self.avg_ms > 100

    @property
    def is_timeout(self) -> bool:
        """Check if this hop timed out (no response)."""
        return self.host == "???" or self.loss_percent == 100.0


@dataclass
class HttpStatResult:
    """Represents httpstat timing results."""

    time_namelookup: int = 0
    time_connect: int = 0
    time_appconnect: int = 0
    time_pretransfer: int = 0
    time_redirect: int = 0
    time_starttransfer: int = 0
    time_total: int = 0
    session_dst: str = ""
    session_src: str = ""
    speed_download: str = ""
    speed_upload: str = ""

    @property
    def dns_ms(self) -> int:
        """DNS lookup time."""
        return self.time_namelookup

    @property
    def tcp_connect_ms(self) -> int:
        """TCP connection time (after DNS)."""
        return self.time_connect - self.time_namelookup

    @property
    def tls_handshake_ms(self) -> int:
        """TLS handshake time (after TCP connect)."""
        return self.time_appconnect - self.time_connect

    @property
    def server_processing_ms(self) -> int:
        """Server processing time (TTFB after TLS)."""
        return self.time_starttransfer - self.time_pretransfer

    @property
    def total_ms(self) -> int:
        """Total request time."""
        return self.time_total


@dataclass
class SipPingResult:
    """Represents sipping.py SIP ping test results."""

    source_ip: str = ""
    dest_ip: str = ""
    port: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    loss_percent: float = 0.0
    avg_latency_ms: float = 0.0
    failed_call_ids: list[str] = field(default_factory=list)

    @property
    def has_loss(self) -> bool:
        """Check if there was any packet loss."""
        return self.loss_percent > 0


@dataclass
class PathmonResult:
    """Represents a complete pathmon result with MTR, httpstat, and sipping data."""

    timestamp: datetime
    source: str
    destination: str
    hops: list[MtrHop] = field(default_factory=list)
    httpstat: HttpStatResult | None = None
    sipping: SipPingResult | None = None
    passed: bool = True
    raw_content: str = ""
    alert_message: str = ""
    latency_threshold: float | None = None
    measured_latency: float | None = None

    @property
    def total_loss(self) -> float:
        """Get the loss at the final hop (destination)."""
        if not self.hops:
            return 0.0
        return self.hops[-1].loss_percent

    @property
    def total_latency(self) -> float:
        """Get the average latency to the destination (from MTR)."""
        if not self.hops:
            return 0.0
        return self.hops[-1].avg_ms

    @property
    def http_latency(self) -> int:
        """Get the HTTP total latency (from httpstat)."""
        if not self.httpstat:
            return 0
        return self.httpstat.time_total

    @property
    def sip_loss(self) -> float:
        """Get the SIP ping packet loss percentage."""
        if not self.sipping:
            return 0.0
        return self.sipping.loss_percent

    @property
    def sip_latency(self) -> float:
        """Get the SIP ping average latency."""
        if not self.sipping:
            return 0.0
        return self.sipping.avg_latency_ms

    @property
    def worst_hop(self) -> MtrHop | None:
        """Find the hop with the highest loss or latency."""
        if not self.hops:
            return None
        return max(self.hops, key=lambda h: (h.loss_percent, h.avg_ms))

    def get_problematic_hops(self) -> list[MtrHop]:
        """Get all hops showing packet loss or high latency."""
        return [h for h in self.hops if h.is_problematic]


# Keep MtrResult as alias for backward compatibility
MtrResult = PathmonResult


class PathmonParser:
    """Parser for pathmon logs containing MTR and httpstat output."""

    HOP_PATTERN = re.compile(
        r"^\s*(\d+)\.\s+"  # Hop number
        r"(AS\S+)\s+"  # ASN
        r"(\S+)\s+"  # Host/IP
        r"([\d.]+)%\s+"  # Loss %
        r"(\d+)\s+"  # Sent
        r"([\d.]+)\s+"  # Last
        r"([\d.]+)\s+"  # Avg
        r"([\d.]+)\s+"  # Best
        r"([\d.]+)\s+"  # Worst
        r"([\d.]+)"  # StDev
    )

    HOP_PATTERN_NO_ASN = re.compile(
        r"^\s*(\d+)\.\s*"  # Hop number
        r"([^\s]+)\s+"  # Host (no ASN prefix)
        r"([\d.]+)%\s+"  # Loss %
        r"(\d+)\s+"  # Sent
        r"([\d.]+)\s+"  # Last
        r"([\d.]+)\s+"  # Avg
        r"([\d.]+)\s+"  # Best
        r"([\d.]+)\s+"  # Worst
        r"([\d.]+)"  # StDev
    )

    ALERT_PATTERN = re.compile(r"Datacenter:(\S+)\s+Latency of ([\d.]+) is over threshold ([\d.]+)")

    SOURCE_DEST_PATTERN = re.compile(r"(\S+)\s+\(([^)]+)\)\s*->\s*(\S+)\s+\(([^)]+)\)")

    HTTPSTAT_PATTERNS = {
        "time_namelookup": re.compile(r"time_namelookup:\s*(\d+)"),
        "time_connect": re.compile(r"time_connect:\s*(\d+)"),
        "time_appconnect": re.compile(r"time_appconnect:\s*(\d+)"),
        "time_pretransfer": re.compile(r"time_pretransfer:\s*(\d+)"),
        "time_redirect": re.compile(r"time_redirect:\s*(\d+)"),
        "time_starttransfer": re.compile(r"time_starttransfer:\s*(\d+)"),
        "time_total": re.compile(r"time_total:\s*(\d+)"),
        "session_dst": re.compile(r"session_dst:\s*(\S+)"),
        "session_src": re.compile(r"session_src:\s*(\S+)"),
        "speed_download": re.compile(r"speed_download:\s*(.+)"),
        "speed_upload": re.compile(r"speed_upload:\s*(.+)"),
    }

    SIPPING_CMD_PATTERN = re.compile(r"sipping\.py\s+.*-S\s+(\S+)\s+-d\s+(\S+)\s+-p\s+(\d+)")

    SIPPING_STATS_PATTERN = re.compile(
        r"(\d+)\s+packets transmitted,\s*(\d+)\s+packets received,\s*([\d.]+)%\s+packet loss,\s*([\d.]+)\s*ms\s+avg"
    )

    SIPPING_CALLID_PATTERN = re.compile(r"^([a-f0-9-]+@[\d.]+)$")

    def parse(
        self,
        content: str,
        timestamp: datetime | None = None,
        passed: bool = True,
    ) -> PathmonResult:
        """Parse pathmon log content into structured result.

        Args:
            content: Raw pathmon log text (MTR + httpstat)
            timestamp: Timestamp of the log (if known)
            passed: Whether this was a passing or failing test

        Returns:
            PathmonResult with parsed MTR and httpstat data
        """
        lines = content.strip().split("\n")

        source = ""
        source_ip = ""
        destination = ""
        dest_ip = ""
        hops = []
        alert_message = ""
        latency_threshold = None
        measured_latency = None
        httpstat_data = {}
        sipping_data = {}
        sipping_call_ids = []

        for line in lines:
            alert_match = self.ALERT_PATTERN.search(line)
            if alert_match:
                alert_message = line.strip()
                measured_latency = float(alert_match.group(2))
                latency_threshold = float(alert_match.group(3))
                continue

            src_dest_match = self.SOURCE_DEST_PATTERN.search(line)
            if src_dest_match:
                source = src_dest_match.group(1)
                source_ip = src_dest_match.group(2)
                destination = src_dest_match.group(3)
                dest_ip = src_dest_match.group(4)
                continue

            sipping_cmd_match = self.SIPPING_CMD_PATTERN.search(line)
            if sipping_cmd_match:
                sipping_data["source_ip"] = sipping_cmd_match.group(1)
                sipping_data["dest_ip"] = sipping_cmd_match.group(2)
                sipping_data["port"] = int(sipping_cmd_match.group(3))
                continue

            sipping_stats_match = self.SIPPING_STATS_PATTERN.search(line)
            if sipping_stats_match:
                sipping_data["packets_sent"] = int(sipping_stats_match.group(1))
                sipping_data["packets_received"] = int(sipping_stats_match.group(2))
                sipping_data["loss_percent"] = float(sipping_stats_match.group(3))
                sipping_data["avg_latency_ms"] = float(sipping_stats_match.group(4))
                continue

            callid_match = self.SIPPING_CALLID_PATTERN.match(line.strip())
            if callid_match:
                sipping_call_ids.append(callid_match.group(1))
                continue

            hop_match = self.HOP_PATTERN.match(line)
            if hop_match:
                hop = MtrHop(
                    hop_number=int(hop_match.group(1)),
                    asn=hop_match.group(2),
                    host=hop_match.group(3),
                    loss_percent=float(hop_match.group(4)),
                    sent=int(hop_match.group(5)),
                    last_ms=float(hop_match.group(6)),
                    avg_ms=float(hop_match.group(7)),
                    best_ms=float(hop_match.group(8)),
                    worst_ms=float(hop_match.group(9)),
                    stdev_ms=float(hop_match.group(10)),
                )
                hops.append(hop)
                continue

            hop_match_no_asn = self.HOP_PATTERN_NO_ASN.match(line)
            if hop_match_no_asn and not line.strip().startswith("HOST:"):
                hop = MtrHop(
                    hop_number=int(hop_match_no_asn.group(1)),
                    host=hop_match_no_asn.group(2),
                    loss_percent=float(hop_match_no_asn.group(3)),
                    sent=int(hop_match_no_asn.group(4)),
                    last_ms=float(hop_match_no_asn.group(5)),
                    avg_ms=float(hop_match_no_asn.group(6)),
                    best_ms=float(hop_match_no_asn.group(7)),
                    worst_ms=float(hop_match_no_asn.group(8)),
                    stdev_ms=float(hop_match_no_asn.group(9)),
                )
                hops.append(hop)
                continue

            for key, pattern in self.HTTPSTAT_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    httpstat_data[key] = match.group(1)
                    break

        httpstat = None
        if httpstat_data:
            httpstat = HttpStatResult(
                time_namelookup=int(httpstat_data.get("time_namelookup", 0)),
                time_connect=int(httpstat_data.get("time_connect", 0)),
                time_appconnect=int(httpstat_data.get("time_appconnect", 0)),
                time_pretransfer=int(httpstat_data.get("time_pretransfer", 0)),
                time_redirect=int(httpstat_data.get("time_redirect", 0)),
                time_starttransfer=int(httpstat_data.get("time_starttransfer", 0)),
                time_total=int(httpstat_data.get("time_total", 0)),
                session_dst=httpstat_data.get("session_dst", ""),
                session_src=httpstat_data.get("session_src", ""),
                speed_download=httpstat_data.get("speed_download", ""),
                speed_upload=httpstat_data.get("speed_upload", ""),
            )

        sipping = None
        if sipping_data:
            sipping = SipPingResult(
                source_ip=sipping_data.get("source_ip", ""),
                dest_ip=sipping_data.get("dest_ip", ""),
                port=sipping_data.get("port", 0),
                packets_sent=sipping_data.get("packets_sent", 0),
                packets_received=sipping_data.get("packets_received", 0),
                loss_percent=sipping_data.get("loss_percent", 0.0),
                avg_latency_ms=sipping_data.get("avg_latency_ms", 0.0),
                failed_call_ids=sipping_call_ids,
            )

        return PathmonResult(
            timestamp=timestamp or datetime.now(),
            source=source or source_ip,
            destination=destination or dest_ip,
            hops=hops,
            httpstat=httpstat,
            sipping=sipping,
            passed=passed,
            raw_content=content,
            alert_message=alert_message,
            latency_threshold=latency_threshold,
            measured_latency=measured_latency,
        )

    def parse_multiple(
        self,
        logs: list[tuple[str, datetime, bool]],
    ) -> list[PathmonResult]:
        """Parse multiple pathmon logs.

        Args:
            logs: List of (content, timestamp, passed) tuples

        Returns:
            List of PathmonResult objects
        """
        return [self.parse(content, timestamp, passed) for content, timestamp, passed in logs]


# Backward compatibility alias
MtrParser = PathmonParser
