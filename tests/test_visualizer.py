"""Tests for the pathmon visualizer."""

import pytest
from datetime import datetime, timezone

from pathmon_analyzer.parser import PathmonResult, MtrHop, HttpStatResult, SipPingResult
from pathmon_analyzer.visualizer import TerminalVisualizer


class TestTerminalVisualizer:
    """Tests for TerminalVisualizer."""

    @pytest.fixture
    def visualizer(self):
        return TerminalVisualizer()

    def test_extract_provider_colt(self, visualizer):
        assert visualizer._extract_provider("ae1.3115.edge7.lon1.neo.colt.net") == "Colt"

    def test_extract_provider_level3(self, visualizer):
        assert visualizer._extract_provider("BICS-SA.ear7.Frankfurt1.Level3.net") == "Level3/Lumen"

    def test_extract_provider_telia(self, visualizer):
        assert visualizer._extract_provider("router.telia.com") == "Telia"

    def test_extract_provider_unknown(self, visualizer):
        assert visualizer._extract_provider("unknown-router.example.com") is None

    def test_find_problematic_provider_hops_skips_hop1(self, visualizer):
        """First hop should be skipped (usually local gateway with ICMP rate limiting)."""
        failures = [
            PathmonResult(
                timestamp=datetime.now(timezone.utc),
                source="src",
                destination="dst",
                hops=[
                    MtrHop(hop_number=1, host="gateway.local", loss_percent=50.0, avg_ms=1.0),
                    MtrHop(hop_number=2, host="router.colt.net", loss_percent=10.0, avg_ms=200.0),
                ],
                passed=False,
            )
        ]
        hops, provider = visualizer._find_problematic_provider_hops(failures)

        assert "gateway.local" not in hops
        assert "router.colt.net" in hops
        assert provider == "Colt"

    def test_find_problematic_provider_hops_prioritizes_provider(self, visualizer):
        """Hops with identifiable providers should be prioritized."""
        failures = [
            PathmonResult(
                timestamp=datetime.now(timezone.utc),
                source="src",
                destination="dst",
                hops=[
                    MtrHop(hop_number=1, host="gateway.local", loss_percent=0.0),
                    MtrHop(hop_number=2, host="unknown.router", loss_percent=20.0, avg_ms=200.0),
                    MtrHop(hop_number=3, host="router.colt.net", loss_percent=15.0, avg_ms=180.0),
                ],
                passed=False,
            )
        ]
        hops, provider = visualizer._find_problematic_provider_hops(failures)

        assert provider == "Colt"
        assert "router.colt.net" in hops

    def test_generate_issue_summary_http_tcp_connect(self, visualizer):
        failures = [
            PathmonResult(
                timestamp=datetime.now(timezone.utc),
                source="src",
                destination="app.example.com",
                httpstat=HttpStatResult(
                    time_namelookup=10,
                    time_connect=600,  # TCP connect = 590ms (elevated)
                    time_total=700,
                ),
                passed=False,
            )
        ]
        summary = visualizer._generate_issue_summary(failures)

        assert "TCP connect time elevated" in summary
        assert "total 700ms" in summary
        assert "app.example.com" in summary

    def test_generate_issue_summary_sip_loss(self, visualizer):
        failures = [
            PathmonResult(
                timestamp=datetime.now(timezone.utc),
                source="src",
                destination="192.168.1.1",
                sipping=SipPingResult(
                    source_ip="10.0.0.1",
                    dest_ip="192.168.1.1",
                    port=5060,
                    packets_sent=50,
                    packets_received=40,
                    loss_percent=20.0,
                    avg_latency_ms=100.0,
                ),
                passed=False,
            )
        ]
        summary = visualizer._generate_issue_summary(failures)

        assert "SIP packet loss (20.0%)" in summary

    def test_generate_issue_summary_sip_latency(self, visualizer):
        failures = [
            PathmonResult(
                timestamp=datetime.now(timezone.utc),
                source="src",
                destination="192.168.1.1",
                sipping=SipPingResult(
                    source_ip="10.0.0.1",
                    dest_ip="192.168.1.1",
                    port=5060,
                    packets_sent=50,
                    packets_received=50,
                    loss_percent=0.0,
                    avg_latency_ms=300.0,  # Elevated
                ),
                passed=False,
            )
        ]
        summary = visualizer._generate_issue_summary(failures)

        assert "SIP latency elevated" in summary

    def test_generate_issue_summary_network_issues_with_provider(self, visualizer):
        failures = [
            PathmonResult(
                timestamp=datetime.now(timezone.utc),
                source="src",
                destination="192.168.1.1",
                hops=[
                    MtrHop(hop_number=1, host="gateway", loss_percent=0.0),
                    MtrHop(hop_number=2, host="router.colt.net", loss_percent=20.0, avg_ms=200.0),
                ],
                passed=False,
            )
        ]
        summary = visualizer._generate_issue_summary(failures)

        assert "network issues at Colt" in summary
        assert "router.colt.net" in summary

    def test_generate_issue_summary_empty_failures(self, visualizer):
        summary = visualizer._generate_issue_summary([])
        assert summary == ""

    def test_generate_issue_summary_fallback(self, visualizer):
        """When no specific issue found, should have a fallback message."""
        failures = [
            PathmonResult(
                timestamp=datetime.now(timezone.utc),
                source="src",
                destination="dst",
                passed=False,
            )
        ]
        summary = visualizer._generate_issue_summary(failures)

        assert "pathmon check failed" in summary
