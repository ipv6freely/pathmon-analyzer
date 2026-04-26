"""Visualization module for MTR analysis results."""

from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .parser import MtrResult, MtrHop, PathmonResult, HttpStatResult, SipPingResult


class TerminalVisualizer:
    """Rich terminal-based visualization for MTR results."""

    def __init__(self):
        self.console = Console()

    def print_summary(self, results: list[MtrResult], pathmon_name: str) -> None:
        """Print a summary of MTR results."""
        if not results:
            self.console.print("[yellow]No results to display[/yellow]")
            return

        failures = [r for r in results if not r.passed]
        avg_latency = sum(r.total_latency for r in results) / len(results)
        avg_loss = sum(r.total_loss for r in results) / len(results)
        max_latency = max(r.total_latency for r in results)
        max_loss = max(r.total_loss for r in results)

        results_with_http = [r for r in results if r.httpstat]
        avg_http_latency = (
            sum(r.http_latency for r in results_with_http) / len(results_with_http)
            if results_with_http
            else 0
        )
        max_http_latency = max((r.http_latency for r in results_with_http), default=0)

        summary = Table(title=f"Pathmon Summary: {pathmon_name}", show_header=False)
        summary.add_column("Metric", style="cyan")
        summary.add_column("Value", style="white")

        summary.add_row("Time Range", f"{results[0].timestamp} → {results[-1].timestamp}")
        summary.add_row("Total Samples", str(len(results)))
        summary.add_row(
            "Failures", f"[red]{len(failures)}[/red]" if failures else "[green]0[/green]"
        )
        summary.add_row("", "")
        summary.add_row("[bold]MTR Metrics[/bold]", "")
        summary.add_row("Avg Latency", f"{avg_latency:.2f} ms")
        summary.add_row(
            "Max Latency", f"[{'red' if max_latency > 100 else 'white'}]{max_latency:.2f} ms[/]"
        )
        summary.add_row("Avg Loss", f"{avg_loss:.2f}%")
        summary.add_row("Max Loss", f"[{'red' if max_loss > 0 else 'white'}]{max_loss:.2f}%[/]")

        if results_with_http:
            summary.add_row("", "")
            summary.add_row("[bold]HTTP Metrics[/bold]", "")
            summary.add_row("Avg HTTP Total", f"{avg_http_latency:.0f} ms")
            summary.add_row(
                "Max HTTP Total",
                f"[{'red' if max_http_latency > 400 else 'white'}]{max_http_latency} ms[/]",
            )

        results_with_sip = [r for r in results if r.sipping]
        if results_with_sip:
            avg_sip_loss = sum(r.sip_loss for r in results_with_sip) / len(results_with_sip)
            max_sip_loss = max(r.sip_loss for r in results_with_sip)
            avg_sip_latency = sum(r.sip_latency for r in results_with_sip) / len(results_with_sip)
            max_sip_latency = max(r.sip_latency for r in results_with_sip)

            summary.add_row("", "")
            summary.add_row("[bold]SIP Metrics[/bold]", "")
            summary.add_row(
                "Avg SIP Loss", f"[{'red' if avg_sip_loss > 0 else 'white'}]{avg_sip_loss:.1f}%[/]"
            )
            summary.add_row(
                "Max SIP Loss", f"[{'red' if max_sip_loss > 0 else 'white'}]{max_sip_loss:.1f}%[/]"
            )
            summary.add_row("Avg SIP Latency", f"{avg_sip_latency:.1f} ms")
            summary.add_row(
                "Max SIP Latency",
                f"[{'red' if max_sip_latency > 200 else 'white'}]{max_sip_latency:.1f} ms[/]",
            )

        self.console.print(summary)

    def print_hops_table(self, result: MtrResult) -> None:
        """Print a detailed hop-by-hop table for a single MTR result."""
        table = Table(
            title=f"MTR Trace @ {result.timestamp}",
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Hop", justify="right", style="dim")
        table.add_column("Host", style="white")
        table.add_column("Loss%", justify="right")
        table.add_column("Sent", justify="right", style="dim")
        table.add_column("Last", justify="right")
        table.add_column("Avg", justify="right")
        table.add_column("Best", justify="right")
        table.add_column("Worst", justify="right")
        table.add_column("StDev", justify="right")

        for hop in result.hops:
            loss_style = "red" if hop.loss_percent > 0 else "green"
            latency_style = "red" if hop.avg_ms > 100 else "white"

            table.add_row(
                str(hop.hop_number),
                hop.host,
                f"[{loss_style}]{hop.loss_percent:.1f}%[/]",
                str(hop.sent),
                f"{hop.last_ms:.1f}",
                f"[{latency_style}]{hop.avg_ms:.1f}[/]",
                f"{hop.best_ms:.1f}",
                f"{hop.worst_ms:.1f}",
                f"{hop.stdev_ms:.1f}",
            )

        self.console.print(table)

    def print_problematic_hops(self, results: list[MtrResult]) -> None:
        """Identify and print hops that consistently show problems."""
        if not results:
            return

        hop_issues: dict[str, dict] = {}

        for result in results:
            for hop in result.get_problematic_hops():
                if hop.host not in hop_issues:
                    hop_issues[hop.host] = {
                        "hop_number": hop.hop_number,
                        "loss_events": 0,
                        "total_loss": 0.0,
                        "latency_events": 0,
                        "total_latency": 0.0,
                        "count": 0,
                    }

                hop_issues[hop.host]["count"] += 1
                if hop.loss_percent > 0:
                    hop_issues[hop.host]["loss_events"] += 1
                    hop_issues[hop.host]["total_loss"] += hop.loss_percent
                if hop.avg_ms > 100:
                    hop_issues[hop.host]["latency_events"] += 1
                    hop_issues[hop.host]["total_latency"] += hop.avg_ms

        if not hop_issues:
            self.console.print(Panel("[green]No problematic hops detected[/green]"))
            return

        table = Table(
            title="Problematic Hops Analysis",
            show_header=True,
            header_style="bold red",
        )

        table.add_column("Hop#", justify="right")
        table.add_column("Host")
        table.add_column("Loss Events", justify="right")
        table.add_column("Avg Loss%", justify="right")
        table.add_column("Latency Events", justify="right")
        table.add_column("Avg Latency", justify="right")

        for host, data in sorted(hop_issues.items(), key=lambda x: x[1]["hop_number"]):
            avg_loss = data["total_loss"] / data["count"] if data["count"] else 0
            avg_latency = data["total_latency"] / data["count"] if data["count"] else 0

            table.add_row(
                str(data["hop_number"]),
                host,
                str(data["loss_events"]),
                f"{avg_loss:.1f}%",
                str(data["latency_events"]),
                f"{avg_latency:.1f} ms",
            )

        self.console.print(table)

    def print_timeline(self, results: list[MtrResult]) -> None:
        """Print a simple ASCII timeline of pass/fail status."""
        if not results:
            return

        self.console.print("\n[bold]Timeline (Pass/Fail):[/bold]")

        timeline = Text()
        for result in results:
            if result.passed:
                timeline.append("●", style="green")
            else:
                timeline.append("●", style="red")

        self.console.print(timeline)
        self.console.print(f"[dim]{results[0].timestamp} → {results[-1].timestamp}[/dim]\n")

    def print_httpstat_table(self, result: PathmonResult) -> None:
        """Print httpstat timing breakdown for a single result."""
        if not result.httpstat:
            return

        http = result.httpstat
        table = Table(
            title=f"HTTP Timing @ {result.timestamp}",
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Phase", style="white")
        table.add_column("Time (ms)", justify="right")
        table.add_column("Cumulative (ms)", justify="right", style="dim")

        table.add_row("DNS Lookup", str(http.dns_ms), str(http.time_namelookup))
        table.add_row("TCP Connect", str(http.tcp_connect_ms), str(http.time_connect))
        table.add_row("TLS Handshake", str(http.tls_handshake_ms), str(http.time_appconnect))
        table.add_row(
            "Server Processing", str(http.server_processing_ms), str(http.time_starttransfer)
        )
        table.add_row(
            "[bold]Total[/bold]",
            f"[{'red' if http.total_ms > 400 else 'green'}]{http.total_ms}[/]",
            "",
        )

        self.console.print(table)

        if http.session_dst:
            self.console.print(f"[dim]Connection: {http.session_src} → {http.session_dst}[/dim]")

    def print_sipping_table(self, result: PathmonResult) -> None:
        """Print sipping.py SIP ping results for a single result."""
        if not result.sipping:
            return

        sip = result.sipping
        table = Table(
            title=f"SIP Ping @ {result.timestamp}",
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Metric", style="white")
        table.add_column("Value", justify="right")

        table.add_row("Destination", f"{sip.dest_ip}:{sip.port}")
        table.add_row("Source", sip.source_ip)
        table.add_row("Packets Sent", str(sip.packets_sent))
        table.add_row("Packets Received", str(sip.packets_received))
        table.add_row(
            "Packet Loss",
            f"[{'red' if sip.loss_percent > 0 else 'green'}]{sip.loss_percent:.1f}%[/]",
        )
        table.add_row(
            "Avg Latency",
            f"[{'red' if sip.avg_latency_ms > 200 else 'white'}]{sip.avg_latency_ms:.1f} ms[/]",
        )

        self.console.print(table)

        if sip.failed_call_ids:
            self.console.print(
                f"[dim]Failed Call-IDs: {len(sip.failed_call_ids)} (first: {sip.failed_call_ids[0]})[/dim]"
            )

    def print_failure_details(self, results: list[PathmonResult]) -> None:
        """Print detailed breakdown of failures."""
        failures = [r for r in results if not r.passed]
        if not failures:
            return

        self.console.print(f"\n[bold red]Failure Details ({len(failures)} failures):[/bold red]\n")

        for result in failures:
            if result.alert_message:
                self.console.print(f"[yellow]{result.alert_message}[/yellow]")

            if result.httpstat:
                self.print_httpstat_table(result)

            if result.sipping:
                self.print_sipping_table(result)

            if result.hops:
                self.print_hops_table(result)

            self.console.print()

        summary = self._generate_issue_summary(failures)
        if summary:
            self.console.print(Panel(summary, title="Summary for PagerDuty", border_style="green"))

    def _extract_provider(self, hostname: str) -> str | None:
        """Extract provider name from hostname if recognizable."""
        hostname_lower = hostname.lower()

        providers = {
            "colt": "Colt",
            "level3": "Level3/Lumen",
            "lumen": "Level3/Lumen",
            "telia": "Telia",
            "zayo": "Zayo",
            "cogent": "Cogent",
            "ntt": "NTT",
            "gtt": "GTT",
            "pccw": "PCCW",
            "tata": "Tata",
            "hurricane": "Hurricane Electric",
            "he.net": "Hurricane Electric",
            "google": "Google",
            "amazon": "AWS",
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "equinix": "Equinix",
            "impsat": "Impsat",
            "algar": "Algar",
        }

        for key, name in providers.items():
            if key in hostname_lower:
                return name
        return None

    def _find_problematic_provider_hops(
        self, failures: list[PathmonResult]
    ) -> tuple[list[str], str | None]:
        """Find problematic hops and identify provider if possible.

        Returns tuple of (hop_hosts, provider_name).
        Skips first hop (usually local gateway with ICMP rate limiting).
        Prioritizes hops with identifiable provider names.
        """
        hop_issues: dict[str, dict] = {}

        for r in failures:
            for hop in r.get_problematic_hops():
                if hop.hop_number == 1:
                    continue

                if hop.loss_percent > 5 or hop.avg_ms > 150:
                    if hop.host not in hop_issues:
                        hop_issues[hop.host] = {
                            "hop_number": hop.hop_number,
                            "loss": hop.loss_percent,
                            "latency": hop.avg_ms,
                            "provider": self._extract_provider(hop.host),
                        }
                    else:
                        hop_issues[hop.host]["loss"] = max(
                            hop_issues[hop.host]["loss"], hop.loss_percent
                        )
                        hop_issues[hop.host]["latency"] = max(
                            hop_issues[hop.host]["latency"], hop.avg_ms
                        )

        if not hop_issues:
            return [], None

        hops_with_provider = [(h, d) for h, d in hop_issues.items() if d["provider"]]
        if hops_with_provider:
            hops_with_provider.sort(key=lambda x: (-x[1]["loss"], -x[1]["latency"]))
            worst_hop, worst_data = hops_with_provider[0]
            other_hops = [h for h, _ in hops_with_provider[1:2]]
            return [worst_hop] + other_hops, worst_data["provider"]

        all_hops = sorted(hop_issues.items(), key=lambda x: (-x[1]["loss"], -x[1]["latency"]))
        return [h for h, _ in all_hops[:2]], None

    def _generate_issue_summary(self, failures: list[PathmonResult]) -> str:
        """Generate a one-sentence summary of the issue for PagerDuty."""
        if not failures:
            return ""

        issues = []

        http_failures = [r for r in failures if r.httpstat]
        if http_failures:
            http = http_failures[0].httpstat
            total_ms = http.time_total

            if http.tcp_connect_ms > 500:
                issues.append(
                    f"TCP connect time elevated ({http.tcp_connect_ms}ms, total {total_ms}ms)"
                )
            elif http.tls_handshake_ms > 500:
                issues.append(
                    f"TLS handshake time elevated ({http.tls_handshake_ms}ms, total {total_ms}ms)"
                )
            elif http.dns_ms > 100:
                issues.append(f"DNS lookup time elevated ({http.dns_ms}ms, total {total_ms}ms)")
            elif http.server_processing_ms > 500:
                issues.append(
                    f"server response time elevated ({http.server_processing_ms}ms, total {total_ms}ms)"
                )
            elif total_ms > 400:
                issues.append(f"HTTP total time elevated ({total_ms}ms)")

        sip_failures = [r for r in failures if r.sipping]
        if sip_failures:
            sip = sip_failures[0].sipping
            if sip.loss_percent > 0:
                issues.append(f"SIP packet loss ({sip.loss_percent:.1f}%)")
            if sip.avg_latency_ms > 200:
                issues.append(f"SIP latency elevated ({sip.avg_latency_ms:.0f}ms)")

        problematic_hops, provider = self._find_problematic_provider_hops(failures)

        if problematic_hops:
            hop_info = ", ".join(problematic_hops)
            if provider:
                issues.append(f"network issues at {provider} ({hop_info})")
            else:
                issues.append(f"network issues at {hop_info}")
        elif any(r.total_loss > 0 for r in failures):
            max_loss = max(r.total_loss for r in failures)
            issues.append(f"MTR packet loss ({max_loss:.1f}%)")

        if any(r.total_latency > 100 for r in failures) and not problematic_hops:
            max_latency = max(r.total_latency for r in failures)
            issues.append(f"network latency elevated ({max_latency:.0f}ms)")

        if not issues:
            if http_failures:
                issues.append("HTTP request exceeded threshold")
            elif sip_failures:
                issues.append("SIP ping check failed")
            else:
                issues.append("pathmon check failed")

        pathmon_name = failures[0].destination or (
            failures[0].sipping.dest_ip if failures[0].sipping else "unknown"
        )
        return f"Issue: {'; '.join(issues)} to {pathmon_name}."


class ChartVisualizer:
    """Plotly-based chart visualization for MTR results."""

    def create_latency_chart(
        self,
        results: list[MtrResult],
        pathmon_name: str,
    ) -> go.Figure:
        """Create a latency over time chart."""
        timestamps = [r.timestamp for r in results]
        latencies = [r.total_latency for r in results]
        passed = [r.passed for r in results]

        fig = go.Figure()

        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=latencies,
                mode="lines+markers",
                name="Latency (ms)",
                line=dict(color="blue"),
                marker=dict(
                    color=["green" if p else "red" for p in passed],
                    size=8,
                ),
            )
        )

        fig.update_layout(
            title=f"Latency Over Time: {pathmon_name}",
            xaxis_title="Time",
            yaxis_title="Latency (ms)",
            hovermode="x unified",
        )

        return fig

    def create_loss_chart(
        self,
        results: list[MtrResult],
        pathmon_name: str,
    ) -> go.Figure:
        """Create a packet loss over time chart."""
        timestamps = [r.timestamp for r in results]
        losses = [r.total_loss for r in results]

        fig = go.Figure()

        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=losses,
                mode="lines+markers",
                name="Loss (%)",
                line=dict(color="red"),
                fill="tozeroy",
                fillcolor="rgba(255, 0, 0, 0.1)",
            )
        )

        fig.update_layout(
            title=f"Packet Loss Over Time: {pathmon_name}",
            xaxis_title="Time",
            yaxis_title="Loss (%)",
            hovermode="x unified",
        )

        return fig

    def create_combined_chart(
        self,
        results: list[MtrResult],
        pathmon_name: str,
    ) -> go.Figure:
        """Create a combined latency and loss chart."""
        timestamps = [r.timestamp for r in results]
        latencies = [r.total_latency for r in results]
        losses = [r.total_loss for r in results]
        passed = [r.passed for r in results]

        fig = make_subplots(
            rows=2,
            cols=1,
            shared_xaxes=True,
            vertical_spacing=0.1,
            subplot_titles=("Latency (ms)", "Packet Loss (%)"),
        )

        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=latencies,
                mode="lines+markers",
                name="Latency",
                line=dict(color="blue"),
                marker=dict(
                    color=["green" if p else "red" for p in passed],
                    size=6,
                ),
            ),
            row=1,
            col=1,
        )

        fig.add_trace(
            go.Scatter(
                x=timestamps,
                y=losses,
                mode="lines+markers",
                name="Loss",
                line=dict(color="red"),
                fill="tozeroy",
                fillcolor="rgba(255, 0, 0, 0.1)",
            ),
            row=2,
            col=1,
        )

        fig.update_layout(
            title=f"Pathmon Analysis: {pathmon_name}",
            height=600,
            hovermode="x unified",
        )

        return fig

    def create_hop_heatmap(
        self,
        results: list[MtrResult],
        pathmon_name: str,
        metric: str = "loss",
    ) -> go.Figure:
        """Create a heatmap showing loss or latency per hop over time."""
        if not results or not results[0].hops:
            return go.Figure()

        timestamps = [r.timestamp.strftime("%H:%M:%S") for r in results]
        hop_hosts = [f"{h.hop_number}. {h.host[:20]}" for h in results[0].hops]

        if metric == "loss":
            data = [[h.loss_percent for h in r.hops] for r in results]
            colorscale = "Reds"
            title = f"Packet Loss Heatmap: {pathmon_name}"
        else:
            data = [[h.avg_ms for h in r.hops] for r in results]
            colorscale = "Blues"
            title = f"Latency Heatmap: {pathmon_name}"

        df = pd.DataFrame(data, index=timestamps, columns=hop_hosts)

        fig = go.Figure(
            data=go.Heatmap(
                z=df.values.T,
                x=df.index,
                y=df.columns,
                colorscale=colorscale,
                hoverongaps=False,
            )
        )

        fig.update_layout(
            title=title,
            xaxis_title="Time",
            yaxis_title="Hop",
            height=400 + len(hop_hosts) * 20,
        )

        return fig

    def save_report(
        self,
        results: list[MtrResult],
        pathmon_name: str,
        output_path: str,
    ) -> None:
        """Save a complete HTML report with all charts."""
        combined = self.create_combined_chart(results, pathmon_name)
        loss_heatmap = self.create_hop_heatmap(results, pathmon_name, "loss")
        latency_heatmap = self.create_hop_heatmap(results, pathmon_name, "latency")

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Pathmon Analysis: {pathmon_name}</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .chart {{ margin-bottom: 40px; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <h1>Pathmon Analysis Report: {pathmon_name}</h1>
    <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p>Time Range: {results[0].timestamp} → {results[-1].timestamp}</p>
    <p>Total Samples: {len(results)}</p>
    
    <div class="chart" id="combined"></div>
    <div class="chart" id="loss_heatmap"></div>
    <div class="chart" id="latency_heatmap"></div>
    
    <script>
        Plotly.newPlot('combined', {combined.to_json()});
        Plotly.newPlot('loss_heatmap', {loss_heatmap.to_json()});
        Plotly.newPlot('latency_heatmap', {latency_heatmap.to_json()});
    </script>
</body>
</html>
"""

        with open(output_path, "w") as f:
            f.write(html_content)
