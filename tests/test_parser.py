"""Tests for the pathmon parser."""

import pytest
from datetime import datetime, timezone

from pathmon_analyzer.parser import (
    PathmonParser,
    MtrHop,
    PathmonResult,
    HttpStatResult,
    SipPingResult,
)


class TestMtrHop:
    """Tests for MtrHop dataclass."""

    def test_is_problematic_with_loss(self):
        hop = MtrHop(hop_number=1, host="router.example.com", loss_percent=5.0)
        assert hop.is_problematic is True

    def test_is_problematic_with_high_latency(self):
        hop = MtrHop(hop_number=1, host="router.example.com", avg_ms=150.0)
        assert hop.is_problematic is True

    def test_is_not_problematic(self):
        hop = MtrHop(hop_number=1, host="router.example.com", loss_percent=0.0, avg_ms=10.0)
        assert hop.is_problematic is False

    def test_is_timeout(self):
        hop = MtrHop(hop_number=1, host="???", loss_percent=100.0)
        assert hop.is_timeout is True

    def test_is_not_timeout(self):
        hop = MtrHop(hop_number=1, host="router.example.com", loss_percent=0.0)
        assert hop.is_timeout is False


class TestHttpStatResult:
    """Tests for HttpStatResult dataclass."""

    def test_timing_properties(self):
        http = HttpStatResult(
            time_namelookup=10,
            time_connect=50,
            time_appconnect=150,
            time_pretransfer=155,
            time_starttransfer=300,
            time_total=350,
        )
        assert http.dns_ms == 10
        assert http.tcp_connect_ms == 40  # 50 - 10
        assert http.tls_handshake_ms == 100  # 150 - 50
        assert http.server_processing_ms == 145  # 300 - 155
        assert http.total_ms == 350


class TestSipPingResult:
    """Tests for SipPingResult dataclass."""

    def test_has_loss_true(self):
        sip = SipPingResult(packets_sent=50, packets_received=40, loss_percent=20.0)
        assert sip.has_loss is True

    def test_has_loss_false(self):
        sip = SipPingResult(packets_sent=50, packets_received=50, loss_percent=0.0)
        assert sip.has_loss is False


class TestPathmonResult:
    """Tests for PathmonResult dataclass."""

    def test_total_loss_from_last_hop(self):
        result = PathmonResult(
            timestamp=datetime.now(timezone.utc),
            source="src",
            destination="dst",
            hops=[
                MtrHop(hop_number=1, host="hop1", loss_percent=0.0),
                MtrHop(hop_number=2, host="hop2", loss_percent=5.0),
            ],
        )
        assert result.total_loss == 5.0

    def test_total_latency_from_last_hop(self):
        result = PathmonResult(
            timestamp=datetime.now(timezone.utc),
            source="src",
            destination="dst",
            hops=[
                MtrHop(hop_number=1, host="hop1", avg_ms=10.0),
                MtrHop(hop_number=2, host="hop2", avg_ms=50.0),
            ],
        )
        assert result.total_latency == 50.0

    def test_get_problematic_hops(self):
        result = PathmonResult(
            timestamp=datetime.now(timezone.utc),
            source="src",
            destination="dst",
            hops=[
                MtrHop(hop_number=1, host="hop1", loss_percent=0.0, avg_ms=10.0),
                MtrHop(hop_number=2, host="hop2", loss_percent=10.0, avg_ms=20.0),
                MtrHop(hop_number=3, host="hop3", loss_percent=0.0, avg_ms=200.0),
            ],
        )
        problematic = result.get_problematic_hops()
        assert len(problematic) == 2
        assert problematic[0].host == "hop2"
        assert problematic[1].host == "hop3"


class TestPathmonParser:
    """Tests for PathmonParser."""

    def test_parse_mtr_with_asn(self):
        content = """Start: 2024-01-15T14:30:00+0000
server1 (10.0.0.1) -> target.example.com (192.168.1.1)
HOST: server1          Loss%   Snt  Last   Avg  Best  Wrst StDev Javg Jint
  1. AS12345  10.0.0.1       0.0%    50   0.3   0.3   0.2   0.4   0.0  0.0  0.4
  2. AS67890  192.168.1.1    0.0%    50   1.5   1.4   1.2   2.0   0.1  0.1  0.2
"""
        parser = PathmonParser()
        result = parser.parse(content, datetime.now(timezone.utc), passed=True)

        assert result.source == "server1"
        assert result.destination == "target.example.com"
        assert len(result.hops) == 2
        assert result.hops[0].asn == "AS12345"
        assert result.hops[0].host == "10.0.0.1"
        assert result.hops[0].loss_percent == 0.0
        assert result.hops[1].asn == "AS67890"

    def test_parse_mtr_without_asn(self):
        content = """Start: 2024-01-15T14:30:00+0000
server1 (10.0.0.1) -> target.example.com (192.168.1.1)
HOST: server1          Loss%   Snt  Last   Avg  Best  Wrst StDev
  1. 10.0.0.1       0.0%    50   0.3   0.3   0.2   0.4   0.0
  2. 192.168.1.1    5.0%    50   1.5   1.4   1.2   2.0   0.1
"""
        parser = PathmonParser()
        result = parser.parse(content, datetime.now(timezone.utc), passed=False)

        assert len(result.hops) == 2
        assert result.hops[0].host == "10.0.0.1"
        assert result.hops[1].loss_percent == 5.0
        assert result.passed is False

    def test_parse_httpstat(self):
        content = """time_namelookup: 10
time_connect: 50
time_appconnect: 150
time_pretransfer: 155
time_redirect: 0
time_starttransfer: 300
time_total: 350
session_dst: app.example.com:443
session_src: 10.0.0.1:54321
speed_download: 1.5 MB/s
speed_upload: 500 KB/s
"""
        parser = PathmonParser()
        result = parser.parse(content, datetime.now(timezone.utc))

        assert result.httpstat is not None
        assert result.httpstat.time_namelookup == 10
        assert result.httpstat.time_connect == 50
        assert result.httpstat.time_total == 350
        assert result.httpstat.session_dst == "app.example.com:443"

    def test_parse_sipping(self):
        content = """/usr/local/sipping/sipping.py  -c 50 -S 10.0.0.1 -d 192.168.1.1 -p 5060 -q
Time: 2024-01-15 14:30:00 UTC

--- Summary of failed Call-IDs: ---
abc12300-def4-5600-7890-abcdef012345@10.0.0.1
abc12300-def4-5600-7890-abcdef012346@10.0.0.1
--- statistics ---
50 packets transmitted, 40 packets received, 20.0% packet loss, 150.5 ms avg latency
"""
        parser = PathmonParser()
        result = parser.parse(content, datetime.now(timezone.utc), passed=False)

        assert result.sipping is not None
        assert result.sipping.source_ip == "10.0.0.1"
        assert result.sipping.dest_ip == "192.168.1.1"
        assert result.sipping.port == 5060
        assert result.sipping.packets_sent == 50
        assert result.sipping.packets_received == 40
        assert result.sipping.loss_percent == 20.0
        assert result.sipping.avg_latency_ms == 150.5
        assert len(result.sipping.failed_call_ids) == 2

    def test_parse_alert_message(self):
        content = """Datacenter:dc1_to_provider:192.168.1.1_outbound Latency of 500.5 is over threshold 300.0
Start: 2024-01-15T14:30:00+0000
server1 (10.0.0.1) -> 192.168.1.1 (192.168.1.1)
"""
        parser = PathmonParser()
        result = parser.parse(content, datetime.now(timezone.utc), passed=False)

        assert "Latency of 500.5 is over threshold 300.0" in result.alert_message
        assert result.measured_latency == 500.5
        assert result.latency_threshold == 300.0

    def test_parse_combined_mtr_and_sipping(self):
        content = """/usr/local/sbin/mtr -4  --report-wide --report-cycles 50 192.168.1.1 --aslookup
Start: 2024-01-15T14:30:00+0000
server1 (10.0.0.1) -> 192.168.1.1 (192.168.1.1)
HOST: server1          Loss%   Snt  Last   Avg  Best  Wrst StDev Javg Jint
  1. AS12345  10.0.0.1       0.0%    50   0.3   0.3   0.2   0.4   0.0  0.0  0.4
  2. AS67890  192.168.1.1    0.0%    50   1.5   1.4   1.2   2.0   0.1  0.1  0.2

/usr/local/sipping/sipping.py  -c 50 -S 10.0.0.1 -d 192.168.1.1 -p 5060 -q
Time: 2024-01-15 14:30:00 UTC

--- statistics ---
50 packets transmitted, 50 packets received, 0.0% packet loss, 100.0 ms avg latency
"""
        parser = PathmonParser()
        result = parser.parse(content, datetime.now(timezone.utc), passed=True)

        assert len(result.hops) == 2
        assert result.sipping is not None
        assert result.sipping.loss_percent == 0.0
        assert result.sipping.avg_latency_ms == 100.0

    def test_parse_multiple(self):
        content1 = "server1 (10.0.0.1) -> target (192.168.1.1)"
        content2 = "server2 (10.0.0.2) -> target (192.168.1.1)"

        parser = PathmonParser()
        results = parser.parse_multiple(
            [
                (content1, datetime.now(timezone.utc), True),
                (content2, datetime.now(timezone.utc), False),
            ]
        )

        assert len(results) == 2
        assert results[0].passed is True
        assert results[1].passed is False
