"""Command-line interface for sigmux."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Tuple

import click

from .backends import REGISTRY, get_backend
from .rule import SigmaRule


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
    for name in sorted(REGISTRY):
        click.echo(name)


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
    help="Write each conversion to <out>/<rule>.<target>.txt instead of stdout.",
)
def convert(path: Path, target_names: Tuple[str, ...], out_dir: Optional[Path]):
    """Convert one Sigma rule file, or every rule in a directory, into one
    or more SIEM query languages."""
    backends = [get_backend(name) for name in target_names]
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    for rule_path in _iter_rule_files(path):
        try:
            rule = _load_rule(rule_path)
        except Exception as exc:  # noqa: BLE001 - surfaced directly to the user
            click.secho(f"[skip] {rule_path}: {exc}", fg="yellow", err=True)
            exit_code = 1
            continue

        for backend in backends:
            try:
                rendered = backend.render(rule)
            except Exception as exc:  # noqa: BLE001
                click.secho(
                    f"[error] {rule_path} -> {backend.name}: {exc}", fg="red", err=True
                )
                exit_code = 1
                continue

            if out_dir:
                out_path = out_dir / f"{rule_path.stem}.{backend.name}.txt"
                out_path.write_text(rendered + "\n", encoding="utf-8")
                click.echo(f"wrote {out_path}")
            else:
                click.secho(f"--- {rule.title} :: {backend.name} ---", fg="cyan", bold=True)
                click.echo(rendered)
                click.echo()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
