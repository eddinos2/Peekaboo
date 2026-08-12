"""Rich-based progress reporter."""

from __future__ import annotations

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()


class ProgressReporter:
    def __init__(self) -> None:
        self._progress: Progress | None = None
        self._task_id: int | None = None

    def start(self, description: str, total: int | None = None) -> None:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        )
        self._progress.start()
        self._task_id = self._progress.add_task(description, total=total)

    def advance(self, message: str | None = None) -> None:
        if self._progress and self._task_id is not None:
            if message:
                self._progress.update(self._task_id, description=message)
            self._progress.advance(self._task_id)

    def stop(self) -> None:
        if self._progress:
            self._progress.stop()
            self._progress = None

    def info(self, message: str) -> None:
        console.print(f"[cyan]→[/cyan] {message}")

    def success(self, message: str) -> None:
        console.print(f"[green]✓[/green] {message}")

    def warn(self, message: str) -> None:
        console.print(f"[yellow]![/yellow] {message}")

    def error(self, message: str) -> None:
        console.print(f"[red]✗[/red] {message}")
