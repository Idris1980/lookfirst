# LookFirst

**See what code does before you run it.**

Code from an AI assistant, a forum or a tutorial often works, and often does more than you think: it opens ports to the whole internet, writes passwords into files, downloads and runs other scripts, or makes itself start every time you log in. LookFirst reads the code, without running it, and shows you:

- **A picture** of what it would build or touch: servers, firewalls, databases, containers, the websites it talks to, files on your computer, programs it starts and packages it pulls in.
- **The risks in plain English**, each with the line it is on and how to fix it.

**Try it in your browser: [idris1980.github.io/lookfirst](https://idris1980.github.io/lookfirst/)** (it runs in the page; your code is not sent anywhere).

It also works as a VS Code extension, as a GitHub Action for pull requests and as a single command-line program. Nothing leaves your computer, unless you ask the AI in VS Code to explain a problem and suggest a fix, and then you see exactly what is sent first.

## What it reads

| Infrastructure | Programs | Package lists |
| --- | --- | --- |
| Terraform (Azure, AWS) | Python | package.json |
| Bicep and ARM templates | JavaScript and TypeScript | requirements.txt |
| docker-compose | Shell scripts | |
| Kubernetes manifests | PowerShell | |
| | Dockerfiles | |

Point it at a whole repository and each folder with code gets its own picture, with an overview that puts the riskiest first.

## What it looks for

- Ports open to the whole internet, such as SSH, RDP and databases
- Passwords, keys and tokens written into the code
- Storage and databases that anyone can reach
- Scripts that download code and run it (`curl … | bash`, `iex (… DownloadString …)`)
- Hidden code that is decoded and run
- Code that reads SSH keys, cloud credentials or browser passwords, especially when it also talks to the internet
- Changes that make something start automatically
- `rm -rf` on a path that may be empty, and other destructive commands
- Antivirus, firewall or certificate checks being switched off
- Package names that look like misspellings of well-known packages, packages installed straight from an address, and extra package servers
- npm install scripts that download or run something
- Privileged containers, the Docker socket mounted into a container, and similar container escapes
- Placeholders someone forgot to fill in, such as `"YOUR_IP_ADDRESS"` or `"<your-subscription-id>"`
- Syntax errors, using the language's own parser

## Using it

**In VS Code:** right-click a file or folder and choose **Show in LookFirst**. Click a box in the picture, or a finding in the list, to jump to that line. Files are also checked when you save them, and right after a larger piece of code is pasted.

**Explain and fix with AI:** next to each finding, and on the light bulb of each squiggle, LookFirst can ask the AI model you already use in VS Code (such as GitHub Copilot) to explain the problem in plain language and suggest a fix. It is off until you turn it on. Only about 30 lines around the problem are sent, with passwords and keys replaced by placeholders such as `«SECRET_1»`; you see the exact text and choose Send or Cancel every time. A suggested fix is shown as a comparison with your code and changes the file only when you choose Apply.

**On the command line:**

```
lookfirst read main.tf
lookfirst read --open ./infra
lookfirst read --format json ./scripts
lookfirst read --format markdown --fail-on high .
lookfirst excerpt --line 42 main.tf
```

`--format` is `text` (the default), `json`, `markdown` or `github` (annotations for GitHub Actions). `--fail-on high` (or `medium`, `low`) exits with code 3 when there is a finding that severe, so a pipeline can stop. `excerpt` prints the lines around a line with secrets masked, as JSON; the extension uses it before it asks an AI model.

### On GitHub

Add LookFirst to a repository, and every pull request shows the problems on the changed lines, a summary on the run page, a comment that stays up to date, and the full picture to download:

```yaml
# .github/workflows/lookfirst.yml
name: LookFirst
on: pull_request
permissions:
  contents: read
  pull-requests: write # for the summary comment
jobs:
  lookfirst:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: Idris1980/lookfirst@v0.6.0
        with:
          path: .          # files or folders, separated by spaces
          fail-on: high    # or medium, low, none
```

The action builds LookFirst from the source of the version you name, so what runs is exactly the code in this repository. It needs no secrets, and in pull requests from forks it still marks the lines; only the comment is skipped.

### In the browser

[idris1980.github.io/lookfirst](https://idris1980.github.io/lookfirst/) has the same reader, compiled to WebAssembly. Paste code, open files or a folder, or try one of the examples. The page may only load its own files, so there is nowhere your code could be sent. Bicep files are the exception that does not work there, because they need Microsoft's compiler.

## Safe by design

- **The code is never run.** It is read as text. Syntax checks ask the language's own parser to read the file (`node --check`, `bash -n`, Python's `ast.parse`, the PowerShell parser), which never runs it. Bicep is compiled locally with `--no-restore`, so no modules are downloaded.
- **Nothing is sent anywhere** by the program. The only exception is the opt-in AI explanation in VS Code, described above.
- **Secrets are masked before anything is shown to an AI model.** Known key formats, values of settings named like passwords, multi-line private keys and long random strings are replaced, and the tests check that no secret in the examples survives masking.
- **The report runs no scripts.** It is a plain HTML page with a Content-Security-Policy that forbids scripts and network access. In VS Code it is shown with scripts switched off; its links can only open files that are part of the report, or ask the AI (which asks you first). The AI's answer is shown as plain text, never as code that runs.
- **A workspace cannot change how the extension behaves.** The program it runs and the AI settings can only be set in your own user settings, so a downloaded repository cannot turn on the AI or stop it from asking.
- **Inputs are limited** in size and number, and symbolic links are not followed.

## Limits

LookFirst tells you what it found. It cannot promise that code is safe: code written to hide what it does can get past any tool that only reads it. A future mode will run code inside an isolated virtual machine and watch what it does.

## Installing

Download the `.vsix` for your platform from [Releases](https://github.com/Idris1980/lookfirst/releases) and install it:

```
code --install-extension lookfirst-win32-x64-0.6.0.vsix
```

Every file in a release is built by GitHub Actions from this repository and signed with Sigstore. Check a file before you install it:

```
gh attestation verify lookfirst-win32-x64-0.6.0.vsix --repo Idris1980/lookfirst
```

Each release also has `SHA256SUMS.txt` and a software bill of materials (`lookfirst.spdx.json`).

## Building

Requires Go 1.27 or later.

```
go test ./...
go build -o lookfirst.exe ./cmd/lookfirst
```

`scripts/build.ps1` builds the program for Windows, macOS and Linux and puts it in the VS Code extension; `scripts/build.ps1 -Package` also makes one `.vsix` per platform.

The examples in `examples/` contain risky code on purpose, with made-up keys and addresses, and the tests check that every one of them is still found.

## License

MIT
