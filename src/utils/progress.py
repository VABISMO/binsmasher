"""
Progress indicators for long-running operations.
Also suppresses pwntools verbose output unless --verbose is set.
"""
from __future__ import annotations
import contextlib
import logging
import os
import sys
from typing import Generator

log = logging.getLogger("binsmasher")


def suppress_pwntools_noise(level: str = "error") -> None:
    """
    Set pwntools log level to suppress connection noise.
    Call once at startup.
    """
    try:
        from pwn import context
        context.log_level = level
    except Exception:
        pass


def restore_pwntools_level(level: str = "info") -> None:
    """Restore pwntools log level."""
    try:
        from pwn import context
        context.log_level = level
    except Exception:
        pass


@contextlib.contextmanager
def quiet_pwntools() -> Generator:
    """Context manager: silence pwntools during a block."""
    try:
        from pwn import context
        old = context.log_level
        context.log_level = "error"
        yield
    except Exception:
        yield
    finally:
        try:
            context.log_level = old
        except Exception:
            pass


class BinSmasherProgress:
    """
    Thin wrapper around Rich Progress for BinSmasher operations.
    Falls back to plain log messages if Rich is not available.
    """

    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self._progress = None
        self._task = None

    def __enter__(self):
        if self.quiet:
            return self
        try:
            from rich.progress import (Progress, SpinnerColumn,
                                        TextColumn, BarColumn,
                                        TaskProgressColumn, TimeElapsedColumn)
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=30),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                transient=True,
            )
            self._progress.start()
        except Exception:
            self._progress = None
        return self

    def __exit__(self, *args):
        if self._progress:
            try:
                self._progress.stop()
            except Exception:
                pass

    def start_task(self, description: str, total: int | None = None) -> object:
        if self._progress:
            self._task = self._progress.add_task(
                description, total=total or 100)
            return self._task
        log.info(description)
        return None

    def update(self, task=None, advance: int = 1,
               description: str | None = None) -> None:
        if self._progress and task is not None:
            kwargs = {"advance": advance}
            if description:
                kwargs["description"] = description
            self._progress.update(task, **kwargs)
        elif description:
            log.info(description)

    def complete(self, task=None, message: str = "Done") -> None:
        if self._progress and task is not None:
            self._progress.update(task, completed=100)
        log.info(message)


def spinner(description: str):
    """Context manager: show a spinner while a block runs."""
    try:
        from rich.console import Console
        from rich.spinner import Spinner
        from rich.live import Live
        console = Console()
        with Live(Spinner("dots", text=description),
                  refresh_per_second=10, console=console):
            yield
    except Exception:
        log.info(description)
        yield


def progress_brute(description: str, total: int, quiet: bool = False):
    """
    Context manager for brute-force loops with progress tracking.

    Usage:
        with progress_brute("Bruting PIE", 512) as update:
            for i, candidate in enumerate(candidates):
                update(i)
                ...
    """
    class _Ctx:
        def __init__(self):
            self._prog = None
            self._task = None
            self._count = 0

        def __enter__(self):
            if not quiet:
                try:
                    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
                    self._prog = Progress(
                        SpinnerColumn(),
                        TextColumn("[cyan]{task.description}"),
                        BarColumn(bar_width=25),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        transient=True)
                    self._prog.start()
                    self._task = self._prog.add_task(description, total=total)
                except Exception:
                    pass
            return self._update

        def _update(self, current: int, status: str | None = None) -> None:
            self._count = current
            if self._prog and self._task is not None:
                kwargs = {"completed": current}
                if status:
                    kwargs["description"] = f"{description} — {status}"
                self._prog.update(self._task, **kwargs)
            elif current % max(1, total // 10) == 0:
                pct = int(100 * current / total) if total else 0
                log.info(f"[brute] {description}: {current}/{total} ({pct}%)")

        def __exit__(self, *args):
            if self._prog:
                try:
                    self._prog.stop()
                except Exception:
                    pass

    return _Ctx()
