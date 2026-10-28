# LookFirst on the command line

The same reader as the VS Code extension and the web page, as one program for Windows, macOS and Linux. Useful in scripts, build pipelines and for checking a whole folder at once.

## Getting the program

Download the file for your computer from the newest [release](https://github.com/Idris1980/lookfirst/releases), for example `lookfirst-win32-x64.exe` on Windows or `lookfirst-darwin-arm64` on a Mac with Apple chip. Rename it to `lookfirst` (or `lookfirst.exe`) and put it in a folder on your `PATH`. On macOS and Linux, make it runnable with `chmod +x lookfirst`.

## Reading code

```
lookfirst read main.tf
lookfirst read --open ./infra
lookfirst read --format json ./scripts
lookfirst read --format markdown --fail-on high .
```

- Without options it prints a summary and writes `lookfirst-report.html` with the picture; `--open` opens it in your browser, `--out` chooses another file name.
- `--format` is `text` (the default), `json`, `markdown` or `github` (markings for GitHub Actions, see [github-action.md](github-action.md)).
- `--fail-on high` (or `medium`, `low`) ends with exit code 3 when there is a finding that severe, so a build pipeline can stop.
- `--changed paths.txt` (one path per line) is for pull requests: the Markdown summary shows the findings in those files first, and `--fail-on` only counts them.
- `--vscode-links` makes the boxes and findings in the report open the code in VS Code; the extension uses it.

## Masked excerpts

```
lookfirst excerpt --line 42 main.tf
```

Prints the lines around line 42 as JSON, with passwords and keys replaced by `«SECRET_1»` and so on. The extension uses it before it shows code to an AI model.

## Comparing a template with Azure or AWS

`lookfirst try` asks Azure what a Bicep or ARM template would really build, or AWS what a CloudFormation template would. See [compare-with-azure.md](compare-with-azure.md).
