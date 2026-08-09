# sigmux

[![CI](https://github.com/kylemain/sigmux/actions/workflows/ci.yml/badge.svg)](https://github.com/kylemain/sigmux/actions/workflows/ci.yml)

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules into multiple SIEM query languages from a single command: **Splunk SPL**, **Elasticsearch Query DSL**, and **Microsoft Sentinel (KQL)**.

```
$ sigmux convert examples/mimikatz_execution.yml

--- Mimikatz Process Execution :: splunk ---
Image=*\mimikatz.exe OR (CommandLine=*sekurlsa::* OR CommandLine=*lsadump::* OR CommandLine=*privilege::debug*)

--- Mimikatz Process Execution :: sentinel ---
DeviceProcessEvents
| where Image endswith "\mimikatz.exe" or (CommandLine has "sekurlsa::" or CommandLine has "lsadump::" or CommandLine has "privilege::debug")

--- Mimikatz Process Execution :: elasticsearch ---
{
  "query": {
    "bool": {
      "should": [
        { "wildcard": { "Image": "*\\mimikatz.exe" } },
        { "bool": { "should": [ ... ], "minimum_should_match": 1 } }
      ],
      "minimum_should_match": 1
    }
  }
}
```

## Why

Detection engineering across more than one SIEM/EDR platform means writing (and maintaining) the same detection logic in several different query languages. Sigma exists to describe detection logic once, vendor-neutrally — `sigmux` is a small, from-scratch implementation of the parts of the Sigma spec that come up constantly in real rules (field matching with `contains`/`startswith`/`endswith`/wildcards, `and`/`or`/`not`, and the `1 of x*` / `all of them` aggregate forms), plus renderers that turn that into query text you can actually paste into Splunk, Elastic, or Sentinel.

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
sigmux convert examples/mimikatz_execution.yml --target splunk

# Convert every rule in a directory, writing output files instead of stdout
sigmux convert examples/ --target elasticsearch --out out/

# List supported targets
sigmux targets
```

## Architecture

```
Sigma YAML  →  rule.py (parse)  →  tiny AST  →  backend.render(rule)  →  query text
                                  (ast_nodes.py)   (backends/*.py)
```

- **`rule.py`** parses a rule's `detection` block into per-selection AST nodes (field matches, ANDed within a selection, ORed across list values), then **`condition_parser.py`** parses the `condition:` string (`and`/`or`/`not`, parentheses, `1 of sel_*`, `all of them`, ...) into a single tree referencing those selections.
- **`ast_nodes.py`** defines the whole tree with four node types: `FieldMatch`, `And`, `Or`, `Not`.
- **`backends/`** each implement one `render(rule) -> str` method that walks the same AST and emits target-specific syntax. Adding a new SIEM target means writing one new backend file — nothing else in the pipeline changes:

```python
class MyBackend(Backend):
    name = "my_siem"

    def render(self, rule: SigmaRule) -> str:
        return _render(rule.ast, top=True)
```

## Known limitations

This is a deliberately-scoped implementation of Sigma's *field matching and boolean logic*, not the full spec:

- Supported field modifiers: exact match (with automatic wildcard inference), `contains`, `startswith`, `endswith`, `re`. Not supported: `base64`, `base64offset`, `cidr`, field-to-field comparisons.
- Supported condition forms: `and` / `or` / `not`, parentheses, `1 of <glob>`, `all of <glob>`, `1 of them`, `all of them`. Not supported: aggregation/timeframe rules (`count() by ... > N`).
- The Sentinel backend's logsource → table mapping covers the common Sigma categories/products out of the box; anything more specific should be overridden per deployment.
- The `re` modifier's Splunk rendering is a best-effort placeholder — SPL doesn't have an inline regex match operator, so the emitted term is flagged with a comment showing the equivalent `| regex` pipe stage.

## Testing

```bash
python -m unittest discover -v
```

27 tests covering field-modifier parsing, the condition-language parser, all three backends, and the CLI.

## License

MIT — see [LICENSE](LICENSE).
