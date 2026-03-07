# gtos — Claude Code Instructions

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
