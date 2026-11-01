# Developing LookFirst

Requires Go 1.27 or later, and Node.js for the extension's tests.

```
go test ./...
go build -o lookfirst.exe ./cmd/lookfirst
node --test "vscode/test/*.test.js"
```

- `scripts/build.ps1` builds the program for Windows, macOS and Linux and puts it in the VS Code extension; `scripts/build.ps1 -Package` also makes one `.vsix` per platform (run `npm ci --ignore-scripts` in `vscode/` first).
- `scripts/build-site.ps1` builds the web page into `bin/site`, with the reader compiled to WebAssembly.
- The examples in `examples/` contain risky code on purpose, with made-up keys and addresses, and the tests check that every one of them is still found. `internal/analyze/testdata/safe` is code written the right way, which must give no high or medium findings.

## Layout

- `cmd/lookfirst` – the command-line program; `cmd/wasm` – the reader for the web page
- `internal/source` – finds files and decides what kind of code each one is
- `internal/terraform`, `arm`, `cloudformation`, `compose`, `kubernetes`, `script` – one reader per kind of code
- `internal/risk` – rules shared by all readers: ports, secrets, placeholders, masking
- `internal/analyze` – runs the readers and groups the results per folder
- `internal/render` – the report (HTML), text, JSON, Markdown, GitHub, Mermaid and draw.io output; `cloudicons/` holds the official Azure and AWS icons (see its NOTICE)
- `internal/advice` – what each finding means, how to fix it, and the AWS Security Hub and Microsoft cloud security benchmark controls behind it; `LOOKFIRST_PRINT_REFS=1 go test ./internal/advice -run TestPrintRefs -v` lists every link for checking
- `internal/azuretry`, `awstry` – compare a template with Azure's or AWS's answer
- `vscode/` – the extension; `site/` – the web page; `action.yml` – the GitHub Action

## Releases

Pushing a tag such as `v0.14.1` (matching `vscode/package.json`) builds, signs and publishes a release through `.github/workflows/release.yml`.
