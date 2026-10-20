# fusion-mcp

A small, dependency-free command-line client for the local MCP server built into Autodesk Fusion.

It lets you inspect documents, capture screenshots, search the Fusion API docs, and run Python scripts inside Fusion, with
a strict set of safety gates in front of everything that can modify your design.

> This project is an independent, community-built tool. It is not affiliated with, endorsed by, or supported by Autodesk.
> "Autodesk" and "Fusion" are trademarks of their respective owners.

## Features

- Standard library only; a single file, `fusion.py`. No `pip install` required.
- Read commands are free: documents, projects, screenshots, API search, Electronics data, and a set of built-in
  read-only inspection scripts (`info`, `tree`, `bodies`, `params`, `timeline`, `props`, `interference`, `fit`).
- Write commands are gated (see [Safety model](#safety-model)).
- Static analysis (lint) of scripts before they are sent to Fusion.
- Append-only audit log of every write attempt, including the SHA-256 of the executed script.
- Connects to loopback addresses only, ignores environment proxies, and never follows redirects.

## Requirements

- Python 3.9 or newer
- Autodesk Fusion with its MCP server enabled (default endpoint: `http://127.0.0.1:27182/mcp`)

## Installation

```sh
git clone https://github.com/<your-user>/fusion-mcp.git
cd fusion-mcp
python3 fusion.py status
```

Optionally install it as a command:

```sh
pip install .
fusion-mcp status
```

## Usage

```sh
# Connection and active document summary
python3 fusion.py status

# Inspect the active design (read-only)
python3 fusion.py info
python3 fusion.py tree
python3 fusion.py bodies
python3 fusion.py params

# Capture a screenshot
python3 fusion.py shot --dir iso-top-right --size 1600x800 --out view.png

# Search the Fusion API documentation
python3 fusion.py api ExtrudeFeatureInput --category class

# Lint a script without connecting to Fusion
python3 fusion.py lint my_script.py

# Run a script (write command; all gates apply)
python3 fusion.py run my_script.py --write --doc "My Design"

# Undo the last operation
python3 fusion.py undo --write --doc "My Design"
```

Run `python3 fusion.py --help` or `python3 fusion.py <command> --help` for the full list of commands and options.

### Script format

Scripts must define the standard Fusion entry point:

```python
import adsk.core, adsk.fusion

def run(_context: str):
    app = adsk.core.Application.get()
    print(app.activeDocument.name)
```

`exec -c "<code>"` accepts inline code. If it does not define `run()`, the code is wrapped for you with `app`, `des`
(the active design) and `root` (the root component) in scope.

## Safety model

Scripts executed through the MCP server run inside Fusion with full privileges. To reduce the risk of accidents, every
write command (`run`, `exec`, `undo`, `redo`, `save`, `open`, `close`, `raw`) must pass all of these gates:

1. **Explicit opt-in**: `--write` or `FUSION_ALLOW_WRITE=1`.
2. **Target document**: `--doc "<name>"` or `FUSION_EXPECT_DOC`. The command aborts if the active document has a different
   name. Use `--any-doc` to deliberately skip this check.
3. **No open command**: the command aborts if Fusion has a command or dialog open, or if the document is read-only.
4. **Confirmation**: an interactive prompt, or `--yes` to skip it. Closing without saving (`close --discard`) always asks.
5. **Static analysis** of scripts: forbidden imports (`os`, `subprocess`, `socket`, ...), forbidden calls (`eval`, `exec`,
   `open`, ...) and sandbox-escape attributes are blocked. Destructive calls (`deleteMe`, `save`, `close`, ...) require
   `--allow-destructive`.

Additional protections:

| Protection | Details |
| --- | --- |
| Local only | Non-loopback URLs are rejected unless `FUSION_MCP_ALLOW_REMOTE=1` is set. |
| No proxies or redirects | Environment proxies are ignored and HTTP redirects are not followed. |
| Size limits | Scripts are limited to 200 KB and responses to 50 MB. |
| Audit log | Write attempts are appended to `audit.jsonl` (mode `0600`). Disable with `--no-audit`. |
| Dry run | `--dry-run` lints and prints what would be sent without sending it. |

**The lint is a safety net against mistakes, not a security boundary.** Do not run scripts you do not trust.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `FUSION_MCP_URL` | MCP server URL | `http://127.0.0.1:27182/mcp` |
| `FUSION_MCP_ALLOW_REMOTE` | Set to `1` to allow non-loopback hosts | unset |
| `FUSION_ALLOW_WRITE` | Set to `1` to allow write commands without `--write` | unset |
| `FUSION_EXPECT_DOC` | Expected active document name for write commands | unset |
| `FUSION_MCP_STATE_DIR` | Directory for the audit log and screenshots | `~/.fusion-mcp` |

## Development

```sh
python3 -m unittest discover -s tests -v
```

## Contributing

Issues and pull requests are welcome. Please keep the tool dependency-free and add tests for any change to the lint or
the safety gates.

## License

[MIT](LICENSE)
