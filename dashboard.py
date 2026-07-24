from datetime import datetime

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


def build_dashboard(database, dribbler):
    stats = database.get_stats()
    header = (
        f"[bold cyan]TCP Tarpit[/]  "
        f"[red]Scanners: {stats['scanner_connections']}[/]  "
        f"[green]Normal: {stats['normal_connections']}[/]  "
        f"[yellow]Active dribbles: {dribbler.active_count()}[/]  "
        f"[white]Total: {stats['total_connections']}[/]  "
        f"[dim]{datetime.now().strftime('%H:%M:%S')}[/]"
    )
    table = Table(title="Recent connections", expand=True)
    table.add_column("Time", no_wrap=True)
    table.add_column("Source")
    table.add_column("Port", justify="right")
    table.add_column("OS")
    table.add_column("Type")
    table.add_column("Status")
    for row in database.get_recent_connections():
        colour = "red" if row["classification"] == "scanner" else "green"
        table.add_row(
            row["timestamp"], f"{row['source_ip']}:{row['source_port']}",
            str(row["destination_port"]), row["spoofed_os"],
            f"[{colour}]{row['classification'].upper()}[/]", row["status"],
        )
    return Group(Panel(header, border_style="cyan"), table)


def run_dashboard(database, dribbler, stop_event):
    with Live(build_dashboard(database, dribbler), refresh_per_second=1, screen=True) as live:
        while not stop_event.wait(1):
            live.update(build_dashboard(database, dribbler))
