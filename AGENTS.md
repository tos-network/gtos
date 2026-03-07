# gtos — Agent Instructions

## Paths

Do not hardcode user-specific absolute home directories such as `/home/<user>`
in repository files, scripts, docs, or systemd templates.

Use one of these instead:

- `$HOME/...` in shell examples and scripts
- `~/...` in human-facing documentation when expansion is only illustrative
- relative repository paths where possible
- runtime-provided environment variables

For systemd units, do not rely on a hardcoded home path. Prefer invoking a
shell that expands `$HOME` for the target user, for example:

```ini
ExecStart=/bin/bash -lc 'exec "$HOME/gtos/scripts/validator_guard.sh"'
```

## Testing

Use `-p` to run package tests in parallel and speed up the suite significantly:

```bash
go test -p 96 ./...
go test -p 96 ./core/... -timeout 300s
go test -p 96 ./core/... ./tos/... ./params/... -count=1 -timeout 300s
```

`-p N` sets the number of packages that can be tested in parallel (default is GOMAXPROCS). On machines with many cores, `-p 96` (or match your CPU count) cuts total wall-clock time drastically.

Single-package runs don't benefit from `-p`; use `-parallel` instead to parallelise test cases within a package:

```bash
go test -parallel 16 ./core -timeout 120s
```
