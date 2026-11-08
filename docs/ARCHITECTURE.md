# Architecture

QA Desktop is a GTK4 shell with a small module contract. It does not embed the
engines or change their storage formats.

## Boundaries

| Module | Integration | Privilege |
| --- | --- | --- |
| Sentinels | Executes the existing `qa` CLI | Same user as the shell |
| Malware Scan | Executes `malware-scan scan --json` and `list` | Same user as the shell |
| SIEM | Calls the loopback HTTP API with a bearer token | Read-only file access to the token |

Commands are built as argument vectors and started with `subprocess.Popen`
without a shell. Output is streamed on a worker thread and delivered to GTK
through `GLib.idle_add`. A module can stop its child process group.

## Module contract

Each module subclasses `qadesk.ui.base.ModulePage` and provides:

- a stable `id`, `title`, `icon`, and description;
- a GTK page built in its constructor;
- `refresh()` for an explicit user refresh;
- `shutdown()` to stop workers and child processes.

`qadesk.modules.MODULE_CLASSES` is the registry used by the shell. Disabled
modules are omitted by the settings dialog; per-module `.desktop` entries start
the same shell focused on one module.

## Configuration

`~/.config/qa-desktop/config.json` stores command overrides, repository roots,
the SIEM URL, token-file path, and enabled modules. Defaults are discovered from
environment variables, `PATH`, and the standard local install locations.
Bearer tokens are never written to this configuration.

## Extension checklist

1. Add a `ModulePage` subclass.
2. Register it in `qadesk/modules/__init__.py`.
3. Add a launcher in `install.sh` if it should appear as a separate desktop app.
4. Keep all external calls shell-free and all UI updates on the GTK thread.
