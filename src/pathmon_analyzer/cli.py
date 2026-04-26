"""CLI interface for pathmon analyzer."""

import subprocess
import sys
from datetime import datetime, timedelta, timezone

import click
from rich.console import Console

from .gcs_client import GcsClient
from .parser import MtrParser
from .visualizer import TerminalVisualizer, ChartVisualizer

console = Console()


def parse_datetime(value: str) -> datetime:
    """Parse datetime from various formats."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    raise click.BadParameter(f"Cannot parse datetime: {value}")


@click.group()
@click.version_option()
@click.option(
    "--bucket",
    "-b",
    envvar="PATHMON_GCS_BUCKET",
    help="GCS bucket name (or set PATHMON_GCS_BUCKET env var)",
)
@click.pass_context
def main(ctx, bucket: str | None):
    """Pathmon Analyzer - Investigate MTR logs from GCS."""
    ctx.ensure_object(dict)
    ctx.obj["bucket"] = bucket


@main.command()
def login():
    """Authenticate with Google Cloud for GCS access."""
    console.print("[bold]Authenticating with Google Cloud...[/bold]\n")

    try:
        result = subprocess.run(
            ["gcloud", "auth", "application-default", "login"],
            check=False,
        )
        if result.returncode == 0:
            console.print("\n[green]Successfully authenticated![/green]")
            console.print("You can now use pathmon commands to access GCS.")
        else:
            console.print("\n[red]Authentication failed.[/red]")
            sys.exit(1)
    except FileNotFoundError:
        console.print("[red]Error: gcloud CLI not found.[/red]")
        console.print("\nInstall it with: [cyan]brew install google-cloud-sdk[/cyan]")
        sys.exit(1)


@main.command()
@click.pass_context
def list_pathmons(ctx):
    """List all available pathmon names."""
    bucket = ctx.obj.get("bucket")
    try:
        client = GcsClient(bucket)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)

    with console.status("Fetching pathmon list..."):
        pathmons = client.list_pathmons()

    console.print(f"\n[bold]Available Pathmons ({len(pathmons)}):[/bold]\n")
    for name in sorted(pathmons):
        console.print(f"  • {name}")


@main.command()
@click.argument("pathmon_name")
@click.option(
    "--alert-time",
    "-t",
    help="Time of the alert (YYYY-MM-DD HH:MM:SS). Defaults to now.",
)
@click.option(
    "--before",
    "-b",
    default=30,
    type=int,
    help="Minutes before alert time to analyze (default: 30)",
)
@click.option(
    "--after",
    "-a",
    default=10,
    type=int,
    help="Minutes after alert time to analyze (default: 10)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Save HTML report to file",
)
@click.option(
    "--show-all-hops",
    is_flag=True,
    help="Show detailed hop tables for each sample",
)
@click.pass_context
def investigate(
    ctx,
    pathmon_name: str,
    alert_time: str | None,
    before: int,
    after: int,
    output: str | None,
    show_all_hops: bool,
):
    """Investigate a pathmon around an alert time.

    PATHMON_NAME: Name of the pathmon to investigate

    Example:
        pathmon investigate my-pathmon -t "2024-01-15 14:30:00" -b 60 -a 15
    """
    if alert_time:
        alert_dt = parse_datetime(alert_time)
    else:
        alert_dt = datetime.now()

    bucket = ctx.obj.get("bucket")
    try:
        client = GcsClient(bucket)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)
    parser = MtrParser()
    term_viz = TerminalVisualizer()

    alert_dt_utc = alert_dt.astimezone(timezone.utc)

    console.print(f"\n[bold]Investigating:[/bold] {pathmon_name}")
    console.print(
        f"[bold]Alert Time:[/bold] {alert_dt.strftime('%Y-%m-%d %H:%M:%S')} (local) / {alert_dt_utc.strftime('%Y-%m-%d %H:%M:%S')} (UTC)"
    )
    console.print(f"[bold]Window:[/bold] -{before}min to +{after}min\n")

    with console.status("Fetching logs from GCS..."):
        log_files = client.fetch_logs_around_time(
            pathmon_name,
            alert_dt,
            minutes_before=before,
            minutes_after=after,
        )

    if not log_files:
        console.print("[red]No logs found in the specified time range.[/red]")
        return

    console.print(f"[green]Found {len(log_files)} log files[/green]\n")

    results = []
    for log_file in log_files:
        if log_file.content:
            result = parser.parse(
                log_file.content,
                timestamp=log_file.timestamp,
                passed=log_file.passed,
            )
            results.append(result)

    term_viz.print_summary(results, pathmon_name)
    console.print()
    term_viz.print_timeline(results)
    term_viz.print_problematic_hops(results)
    term_viz.print_failure_details(results)

    if show_all_hops:
        console.print("\n[bold]Detailed Hop Tables:[/bold]\n")
        for result in results:
            term_viz.print_hops_table(result)
            console.print()

    if output:
        chart_viz = ChartVisualizer()
        chart_viz.save_report(results, pathmon_name, output)
        console.print(f"\n[green]Report saved to: {output}[/green]")


@main.command()
@click.argument("pathmon_name")
@click.option(
    "--start",
    "-s",
    help="Start time (YYYY-MM-DD HH:MM:SS). Defaults to start of today.",
)
@click.option(
    "--end",
    "-e",
    help="End time (YYYY-MM-DD HH:MM:SS). Defaults to now.",
)
@click.option(
    "--failures-only",
    "-f",
    is_flag=True,
    help="Only show failed tests",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Save HTML report to file",
)
@click.pass_context
def analyze(
    ctx,
    pathmon_name: str,
    start: str | None,
    end: str | None,
    failures_only: bool,
    output: str | None,
):
    """Analyze a pathmon over a time range.

    PATHMON_NAME: Name of the pathmon to analyze

    Example:
        pathmon analyze my-pathmon -s "2024-01-15 00:00" -e "2024-01-15 23:59"
        pathmon analyze my-pathmon  # analyzes today
    """
    if start:
        start_dt = parse_datetime(start)
    else:
        start_dt = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    end_dt = parse_datetime(end) if end else datetime.now()

    bucket = ctx.obj.get("bucket")
    try:
        client = GcsClient(bucket)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)
    parser = MtrParser()
    term_viz = TerminalVisualizer()

    console.print(f"\n[bold]Analyzing:[/bold] {pathmon_name}")
    console.print(f"[bold]Time Range:[/bold] {start_dt} → {end_dt}\n")

    with console.status("Fetching logs from GCS..."):
        log_files = list(
            client.list_logs(
                pathmon_name,
                start_time=start_dt,
                end_time=end_dt,
                only_failures=failures_only,
            )
        )

        for log_file in log_files:
            client.fetch_log_content(log_file)

    if not log_files:
        console.print("[red]No logs found in the specified time range.[/red]")
        return

    console.print(f"[green]Found {len(log_files)} log files[/green]\n")

    results = []
    for log_file in sorted(log_files, key=lambda x: x.timestamp):
        if log_file.content:
            result = parser.parse(
                log_file.content,
                timestamp=log_file.timestamp,
                passed=log_file.passed,
            )
            results.append(result)

    term_viz.print_summary(results, pathmon_name)
    console.print()
    term_viz.print_timeline(results)
    term_viz.print_problematic_hops(results)

    if output:
        chart_viz = ChartVisualizer()
        chart_viz.save_report(results, pathmon_name, output)
        console.print(f"\n[green]Report saved to: {output}[/green]")


@main.command()
@click.argument("pathmon_name")
@click.option(
    "--hours",
    "-h",
    default=1,
    type=int,
    help="Hours of recent data to show (default: 1)",
)
@click.pass_context
def recent(ctx, pathmon_name: str, hours: int):
    """Show recent status for a pathmon.

    PATHMON_NAME: Name of the pathmon to check

    Example:
        pathmon recent my-pathmon -h 2
    """
    end_dt = datetime.now()
    start_dt = end_dt - timedelta(hours=hours)

    bucket = ctx.obj.get("bucket")
    try:
        client = GcsClient(bucket)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise SystemExit(1)
    parser = MtrParser()
    term_viz = TerminalVisualizer()

    console.print(f"\n[bold]Recent Status:[/bold] {pathmon_name}")
    console.print(f"[bold]Last {hours} hour(s)[/bold]\n")

    with console.status("Fetching logs from GCS..."):
        log_files = list(
            client.list_logs(
                pathmon_name,
                start_time=start_dt,
                end_time=end_dt,
            )
        )

        for log_file in log_files:
            client.fetch_log_content(log_file)

    if not log_files:
        console.print("[red]No logs found in the specified time range.[/red]")
        return

    results = []
    for log_file in sorted(log_files, key=lambda x: x.timestamp):
        if log_file.content:
            result = parser.parse(
                log_file.content,
                timestamp=log_file.timestamp,
                passed=log_file.passed,
            )
            results.append(result)

    term_viz.print_summary(results, pathmon_name)
    console.print()
    term_viz.print_timeline(results)

    failures = [r for r in results if not r.passed]
    if failures:
        console.print(f"\n[bold red]Recent Failures ({len(failures)}):[/bold red]")
        for result in failures[-5:]:
            term_viz.print_hops_table(result)
            console.print()


if __name__ == "__main__":
    main()
