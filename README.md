# sigmux

[![CI](https://github.com/kylemain/sigmux/actions/workflows/ci.yml/badge.svg)](https://github.com/kylemain/sigmux/actions/workflows/ci.yml)
[![coverage](coverage.svg)](#testing)
[![PyPI](https://img.shields.io/pypi/v/sigmux)](https://pypi.org/project/sigmux/)

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules into **seven** SIEM/XDR query languages from a single command: **Splunk SPL**, **Elasticsearch Query DSL**, **Microsoft Sentinel (KQL)**, **CrowdStrike Falcon LogScale (LQL)**, **IBM QRadar (AQL)**, **Google Chronicle (YARA-L 2.0)**, and **Sumo Logic**.

This mirrors real multi-SIEM detection engineering work -- writing detection logic once and deploying it consistently across platforms instead of hand-porting query syntax every time a team adds a new SIEM. It pairs directly with [detectl](https://github.com/kylemain/detectl), which takes sigmux's output the rest of the way and actually pushes it to a live platform -- see [Pairs well with detectl](#pairs-well-with-detectl) below.

![sigmux and detectl demo](demo.gif)

```
$ sigmux convert examples/mimikatz_execution.yml --target splunk --target sentinel --target elastic

╭─ Mimikatz Process Execution :: splunk (Splunk SPL) ──────────────────────────╮
│ Image=*\mimikatz.exe OR (CommandLine=*sekurlsa::* OR CommandLine=*lsadump::* │
│ OR CommandLine=*privilege::debug*)                                           │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Mimikatz Process Execution :: sentinel (Microsoft Sentinel (KQL)) ──────────╮
│ DeviceProcessEvents                                                          │
│ | where Image endswith "\mimikatz.exe" or (CommandLine has "sekurlsa::" or   │
│ CommandLine has "lsadump::" or CommandLine has "privilege::debug")           │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Mimikatz Process Execution :: elastic (Elasticsearch Query DSL) ────────────╮
│ { "query": { "bool": { "should": [ ... ], "minimum_should_match": 1 } } }    │
╰──────────────────────────────────────────────────────────────────────────────╯
3 conversion(s) across 1 rule(s), 0 error(s)
```

Each target gets its own colored, syntax-highlighted panel in the terminal (JSON, SQL, and YARA-L output get real Pygments highlighting via [rich](https://github.com/Textualize/rich)); `sigmux targets` prints a table of every supported target, its query language, and its output file extension.

## Why

Detection engineering across more than one SIEM/EDR platform means writing (and maintaining) the same detection logic in several different query languages. Sigma exists to describe detection logic once, vendor-neutrally — `sigmux` is a small, from-scratch implementation of the parts of the Sigma spec that come up constantly in real rules (field matching with `contains`/`startswith`/`endswith`/wildcards, `and`/`or`/`not`, and the `1 of x*` / `all of them` aggregate forms), plus renderers that turn that into query text you can actually paste into your platform of choice.

It's a generalized, from-scratch build — not a wrapper around an existing rule-conversion library — written to be small enough to read end to end in one sitting.

## Install

Published on PyPI. In a fresh terminal, with no prior setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install sigmux
```

(`pip install sigmux` alone -- outside a venv -- will likely be refused on a modern Mac; recent Python installs block bare system-wide installs on purpose. The two lines above sidestep that.)

Prefer [pipx](https://pipx.pypa.io) for a CLI tool like this and don't want to think about venvs at all: `pipx install sigmux`.

The Usage examples below reference files under `examples/`, so to run them verbatim (rather than pointing sigmux at a Sigma rule of your own), clone the repo instead and install in editable mode:

```bash
git clone https://github.com/kylemain/sigmux
cd sigmux
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Convert a single rule to every supported target
sigmux convert examples/mimikatz_execution.yml

# Convert to specific target(s) only
sigmux convert examples/mimikatz_execution.yml --target splunk --target crowdstrike

# Convert every rule in a directory, writing output files instead of stdout
sigmux convert examples/ --target elastic --out out/

# List supported targets, their query language, and output extension
sigmux targets
```

```
                   sigmux conversion targets
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Target      ┃ Query language                    ┃ Output ext ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ chronicle   │ Google Chronicle (YARA-L 2.0)     │   .yaral   │
│ crowdstrike │ CrowdStrike Falcon LogScale (LQL) │    .lql    │
│ elastic     │ Elasticsearch Query DSL           │   .json    │
│ qradar      │ IBM QRadar (AQL)                  │    .aql    │
│ sentinel    │ Microsoft Sentinel (KQL)          │    .kql    │
│ splunk      │ Splunk SPL                        │    .spl    │
│ sumologic   │ Sumo Logic search query           │   .sumo    │
└─────────────┴───────────────────────────────────┴────────────┘
```

## Pairs well with [detectl](https://github.com/kylemain/detectl)

sigmux's target names match detectl's platform names 1:1 on purpose (`elastic`, `crowdstrike`, `sentinel`, `splunk`, `qradar`, `sumologic`, `chronicle`) -- the conversion target and the platform you push it to are never something you have to look up a mapping for.

detectl imports sigmux as a library to collapse the two-step "convert, then paste the output into a create command" workflow into one -- try it (no credentials needed with `--dry-run`):

```bash
pip install "detectl[sigma,dryrun]"
curl -o mimikatz.yml https://raw.githubusercontent.com/kylemain/sigmux/main/examples/mimikatz_execution.yml
detectl -p elastic rules create-from-sigma mimikatz.yml --dry-run
```

That single command parses the Sigma rule, converts it with sigmux using the exact target that matches `--platform`, and creates it as a live detection rule -- with a `--dry-run` flag that shows the full converted query and rule metadata (Terraform-plan style) before anything is actually created. This isn't just a documented pairing either: a separate `integration` CI job in detectl spins up a real Elasticsearch and runs this exact pipeline against it end to end (see detectl's `scripts/integration_test_elastic.py`), so the two projects staying compatible is something CI actually checks, not just a README claim.

## Architecture

```
Sigma YAML  →  rule.py (parse)  →  tiny AST  →  backend.render(rule)  →  query text
                                  (ast_nodes.py)   (backends/*.py)
```

- **`rule.py`** parses a rule's `detection` block into per-selection AST nodes (field matches, ANDed within a selection, ORed across list values), then **`condition_parser.py`** parses the `condition:` string (`and`/`or`/`not`, parentheses, `1 of sel_*`, `all of them`, ...) into a single tree referencing those selections.
- **`ast_nodes.py`** defines the whole tree with four node types: `FieldMatch`, `And`, `Or`, `Not`.
- **`backends/`** each implement one `render(rule) -> str` method that walks the same AST and emits target-specific syntax. Adding a new SIEM target means writing one new backend file and registering it in `backends/__init__.py`'s `REGISTRY` — nothing else in the conversion pipeline changes:

```python
class MyBackend(Backend):
    name = "my_siem"

    def render(self, rule: SigmaRule) -> str:
        return _render(rule.ast, top=True)
```

  The CLI's `_TARGET_INFO` dict in `cli.py` adds a display label/color/syntax-highlighting lexer per target for `targets` and `convert`'s panels, but it's cosmetic only — a target missing from it still converts and writes files correctly with a plain fallback label/extension.
- **`cli.py`** wires it all together with [Click](https://click.palletsprojects.com/) for argument parsing and [rich](https://github.com/Textualize/rich) for colored tables, bordered per-target panels, and Pygments-backed syntax highlighting of the rendered query text.

## Known limitations

This is a deliberately-scoped implementation of Sigma's *field matching and boolean logic*, not the full spec:

- Supported field modifiers: exact match (with automatic wildcard inference), `contains`, `startswith`, `endswith`, `re`. `base64`, `base64offset`, `cidr`, and field-to-field comparisons aren't supported -- rather than rejecting the whole rule, an unsupported modifier degrades to a plain exact-match on the raw field value, so the rule still converts (just not perfectly; don't rely on it decoding base64 or matching a CIDR range for you).
- Supported condition forms: `and` / `or` / `not`, parentheses, `1 of <glob>`, `all of <glob>`, `1 of them`, `all of them`. Not supported: aggregation/timeframe rules (`count() by ... > N`) and the newer multi-rule `correlation:` type.
- The Sentinel backend's logsource → table mapping, and the Chronicle backend's logsource → UDM `event_type` mapping, cover the common Sigma categories/products out of the box; anything more specific should be overridden per deployment.
- The `re` modifier's Splunk and Sumo Logic rendering is a best-effort placeholder — neither SPL nor Sumo's search syntax has an inline regex match operator, so the emitted term is flagged with a comment showing the equivalent pipe stage (`| regex` / `| where ... matches`).
- The QRadar backend emits raw Sigma field names, not real AQL property names or a QID map, and doesn't add a `LAST <n> <unit>` time-window clause — both are deployment-specific.
- The Chronicle backend emits raw Sigma field names under the event variable (`$e.Image`) rather than mapping them onto Chronicle's UDM schema (`$e.target.process.file.full_path`, ...) — that mapping is log-source-specific and out of scope here.

## SigmaHQ compatibility

The 9 example rules in this repo prove the mechanics work; they don't prove much about coverage. `scripts/benchmark_sigmahq.py` runs every rule in the real, actively-maintained [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) `rules/` corpus (rules this project doesn't own or control) through every sigmux backend and reports how many convert cleanly:

```bash
python scripts/benchmark_sigmahq.py
```

As of this writing, against the current `rules/` corpus:

```
3141/3141 rules converted cleanly to all 7 targets (100.0%)
```

Read that number for what it actually measures, not more: it means every rule parsed and every backend rendered *something* without raising -- it doesn't mean every rendered query is semantically perfect. 28 of those 3,141 rules use `base64`/`cidr` modifiers, which (per Known limitations above) sigmux intentionally degrades to a plain exact-match rather than rejecting; this snapshot of the corpus also happens to contain zero aggregation/`correlation:` rules, which remain genuinely unsupported and would fail if present. This job runs weekly in CI (informational only, not a merge gate, since it depends on an external repo's content) -- see the `sigmahq-benchmark` job in `.github/workflows/ci.yml`.

## Testing

```bash
python -m unittest discover -v
```

36 tests covering field-modifier parsing, the condition-language parser, all seven backends, and the CLI.

## License

MIT — see [LICENSE](LICENSE).
