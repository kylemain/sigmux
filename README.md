# sigmux

[![CI](https://github.com/kylemain/sigmux/actions/workflows/ci.yml/badge.svg)](https://github.com/kylemain/sigmux/actions/workflows/ci.yml)

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules into **seven** SIEM/XDR query languages from a single command: **Splunk SPL**, **Elasticsearch Query DSL**, **Microsoft Sentinel (KQL)**, **CrowdStrike Falcon LogScale (LQL)**, **IBM QRadar (AQL)**, **Google Chronicle (YARA-L 2.0)**, and **Sumo Logic**.

```
$ sigmux convert examples/mimikatz_execution.yml --target splunk --target sentinel --target elasticsearch

╭─ Mimikatz Process Execution :: splunk (Splunk SPL) ──────────────────────────╮
│ Image=*\mimikatz.exe OR (CommandLine=*sekurlsa::* OR CommandLine=*lsadump::* │
│ OR CommandLine=*privilege::debug*)                                           │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Mimikatz Process Execution :: sentinel (Microsoft Sentinel (KQL)) ──────────╮
│ DeviceProcessEvents                                                          │
│ | where Image endswith "\mimikatz.exe" or (CommandLine has "sekurlsa::" or   │
│ CommandLine has "lsadump::" or CommandLine has "privilege::debug")           │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Mimikatz Process Execution :: elasticsearch (Elasticsearch Query DSL) ──────╮
│ { "query": { "bool": { "should": [ ... ], "minimum_should_match": 1 } } }    │
╰──────────────────────────────────────────────────────────────────────────────╯
3 conversion(s) across 1 rule(s), 0 error(s)
```

Each target gets its own colored, syntax-highlighted panel in the terminal (JSON, SQL, and YARA-L output get real Pygments highlighting via [rich](https://github.com/Textualize/rich)); `sigmux targets` prints a table of every supported target, its query language, and its output file extension.

## Why

Detection engineering across more than one SIEM/EDR platform means writing (and maintaining) the same detection logic in several different query languages. Sigma exists to describe detection logic once, vendor-neutrally — `sigmux` is a small, from-scratch implementation of the parts of the Sigma spec that come up constantly in real rules (field matching with `contains`/`startswith`/`endswith`/wildcards, `and`/`or`/`not`, and the `1 of x*` / `all of them` aggregate forms), plus renderers that turn that into query text you can actually paste into your platform of choice.

It's a generalized, from-scratch build — not a wrapper around an existing rule-conversion library — written to be small enough to read end to end in one sitting.

## Install

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
sigmux convert examples/mimikatz_execution.yml --target splunk --target logscale

# Convert every rule in a directory, writing output files instead of stdout
sigmux convert examples/ --target elasticsearch --out out/

# List supported targets, their query language, and output extension
sigmux targets
```

```
                    sigmux conversion targets
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Target        ┃ Query language                    ┃ Output ext ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ chronicle     │ Google Chronicle (YARA-L 2.0)     │   .yaral   │
│ elasticsearch │ Elasticsearch Query DSL           │   .json    │
│ logscale      │ CrowdStrike Falcon LogScale (LQL) │    .lql    │
│ qradar        │ IBM QRadar (AQL)                  │    .aql    │
│ sentinel      │ Microsoft Sentinel (KQL)          │    .kql    │
│ splunk        │ Splunk SPL                        │    .spl    │
│ sumologic     │ Sumo Logic search query           │   .sumo    │
└───────────────┴───────────────────────────────────┴────────────┘
```

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

- Supported field modifiers: exact match (with automatic wildcard inference), `contains`, `startswith`, `endswith`, `re`. Not supported: `base64`, `base64offset`, `cidr`, field-to-field comparisons.
- Supported condition forms: `and` / `or` / `not`, parentheses, `1 of <glob>`, `all of <glob>`, `1 of them`, `all of them`. Not supported: aggregation/timeframe rules (`count() by ... > N`).
- The Sentinel backend's logsource → table mapping, and the Chronicle backend's logsource → UDM `event_type` mapping, cover the common Sigma categories/products out of the box; anything more specific should be overridden per deployment.
- The `re` modifier's Splunk and Sumo Logic rendering is a best-effort placeholder — neither SPL nor Sumo's search syntax has an inline regex match operator, so the emitted term is flagged with a comment showing the equivalent pipe stage (`| regex` / `| where ... matches`).
- The QRadar backend emits raw Sigma field names, not real AQL property names or a QID map, and doesn't add a `LAST <n> <unit>` time-window clause — both are deployment-specific.
- The Chronicle backend emits raw Sigma field names under the event variable (`$e.Image`) rather than mapping them onto Chronicle's UDM schema (`$e.target.process.file.full_path`, ...) — that mapping is log-source-specific and out of scope here.

## Testing

```bash
python -m unittest discover -v
```

36 tests covering field-modifier parsing, the condition-language parser, all seven backends, and the CLI.

## License

MIT — see [LICENSE](LICENSE).
