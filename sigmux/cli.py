"""Command-line interface for sigmux."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Tuple

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from .backends import REGISTRY, get_backend
from .rule import SigmaRule

console = Console()
err_console = Console(stderr=True)

# Display metadata for the CLI only -- purely cosmetic. A new backend works
# fully (conversion, file output, `targets` listing) with zero entries here;
# omitting one just falls back to a plain label/extension/color, so adding a
# SIEM target still only means writing one new backends/*.py file.
_TARGET_INFO = {
    "splunk": {"label": "Splunk SPL", "ext": "spl", "color": "orange3", "lexer": "text"},
    "elastic": {"label": "Elasticsearch Query DSL", "ext": "json", "color": "gold3", "lexer": "json"},
    "sentinel": {"label": "Microsoft Sentinel (KQL)", "ext": "kql", "color": "deep_sky_blue1", "lexer": "kql"},
    "crowdstrike": {"label": "CrowdStrike Falcon LogScale (LQL)", "ext": "lql", "color": "magenta1", "lexer": "text"},
    "qradar": {"label": "IBM QRadar (AQL)", "ext": "aql", "color": "green3", "lexer": "sql"},
    "chronicle": {"label": "Google Chronicle (YARA-L 2.0)", "ext": "yaral", "color": "cyan1", "lexer": "yara"},
    "sumologic": {"label": "Sumo Logic search query", "ext": "sumo", "color": "red3", "lexer": "text"},
}


def _info_for(target_name: str) -> dict:
    info = _TARGET_INFO.get(target_name, {})
    return {
        "label": info.get("label", target_name.title()),
        "ext": info.get("ext", "txt"),
        "color": info.get("color", "white"),
        "lexer": info.get("lexer", "text"),
    }


def _syntax_for(code: str, target_name: str) -> Syntax:
    lexer = _info_for(target_name)["lexer"]
    try:
        return Syntax(code, lexer, theme="ansi_dark", word_wrap=True, background_color="default")
    except Exception:  # noqa: BLE001 - any lexer/theme hiccup, just fall back
        return Syntax(code, "text", theme="ansi_dark", word_wrap=True, background_color="default")


def _load_rule(path: Path) -> SigmaRule:
    return SigmaRule.from_yaml(path.read_text(encoding="utf-8"))


def _iter_rule_files(path: Path):
    if path.is_dir():
        files = sorted(path.rglob("*.yml")) + sorted(path.rglob("*.yaml"))
        yield from files
    else:
        yield path


@click.group()
@click.version_option(package_name="sigmux")
def main():
    """sigmux -- convert Sigma detection rules into multiple SIEM query languages."""


@main.command()
def targets():
    """List supported conversion targets."""
    table = Table(title="sigmux conversion targets", header_style="bold")
    table.add_column("Target", style="bold")
    table.add_column("Query language")
    table.add_column("Output ext", justify="center")

    for name in sorted(REGISTRY):
        info = _info_for(name)
        table.add_row(f"[{info['color']}]{name}[/{info['color']}]", info["label"], f".{info['ext']}")

    console.print(table)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--target",
    "-t",
    "target_names",
    multiple=True,
    default=tuple(sorted(REGISTRY)),
    help="Target SIEM(s) to convert to. Repeatable. Defaults to all targets.",
)
@click.option(
    "--out",
    "-o",
    "out_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Write each conversion to <out>/<rule>.<target>.<ext> instead of stdout "
    "(.spl, .json, .kql, .lql, .aql, .yaral, .sumo depending on target).",
)
def convert(path: Path, target_names: Tuple[str, ...], out_dir: Optional[Path]):
    """Convert one Sigma rule file, or every rule in a directory, into one
    or more SIEM query languages."""
    backends = [get_backend(name) for name in target_names]
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    rule_count = 0
    ok_count = 0
    error_count = 0

    for rule_path in _iter_rule_files(path):
        try:
            rule = _load_rule(rule_path)
        except Exception as exc:  # noqa: BLE001 - surfaced directly to the user
            err_console.print(f"[bold yellow]⚠ skip[/bold yellow] {rule_path}: {exc}")
            exit_code = 1
            error_count += 1
            continue

        rule_count += 1
        for backend in backends:
            info = _info_for(backend.name)
            try:
                rendered = backend.render(rule)
            except Exception as exc:  # noqa: BLE001
                err_console.print(
                    f"[bold red]✗ error[/bold red] {rule_path} -> {backend.name}: {exc}"
                )
                exit_code = 1
                error_count += 1
                continue

            ok_count += 1
            if out_dir:
                out_path = out_dir / f"{rule_path.stem}.{backend.name}.{info['ext']}"
                out_path.write_text(rendered + "\n", encoding="utf-8")
                console.print(f"[green]✓[/green] wrote [bold]{out_path}[/bold]")
            else:
                title = f"[bold]{rule.title}[/bold] :: [{info['color']}]{backend.name}[/{info['color']}] ({info['label']})"
                console.print(Panel(_syntax_for(rendered, backend.name), title=title, title_align="left", border_style=info["color"]))

    summary_style = "bold green" if error_count == 0 else "bold yellow"
    console.print(
        f"[{summary_style}]{ok_count} conversion(s) across {rule_count} rule(s), "
        f"{error_count} error(s)[/{summary_style}]"
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
