# LookFirst

**See what code does before you run it.**

Code from an AI assistant, a forum or a tutorial often works, and often does more than you think: it opens ports to the whole internet, writes passwords into files, downloads and runs other scripts, or makes itself start every time you log in. LookFirst reads the code, without running it, and shows you:

- **A picture** of what it would build or touch: servers, firewalls, databases, containers, the websites it talks to, files on your computer, programs it starts and packages it pulls in.
- **The risks in plain English**, each with the line it is on and how to fix it.

It works as a VS Code extension and as a single command-line program, and nothing leaves your computer.

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
- Syntax errors, using the language's own parser

## Using it

**In VS Code:** right-click a file or folder and choose **Show in LookFirst**. Click a box in the picture, or a finding in the list, to jump to that line. Files are also checked when you save them, and right after a larger piece of code is pasted.

**On the command line:**

```
lookfirst read main.tf
lookfirst read --open ./infra
lookfirst read --format json ./scripts
```

## Safe by design

- **The code is never run.** It is read as text. Syntax checks ask the language's own parser to read the file (`node --check`, `bash -n`, Python's `ast.parse`, the PowerShell parser), which never runs it. Bicep is compiled locally with `--no-restore`, so no modules are downloaded.
- **Nothing is sent anywhere.** LookFirst makes no network requests.
- **The report runs no scripts.** It is a plain HTML page with a Content-Security-Policy that forbids scripts and network access. In VS Code it is shown with scripts switched off; its links can only open files that are part of the report.
- **A workspace cannot change which program the extension runs.** That setting can only be set in your own user settings.
- **Inputs are limited** in size and number, and symbolic links are not followed.

## Limits

LookFirst tells you what it found. It cannot promise that code is safe: code written to hide what it does can get past any tool that only reads it. A future mode will run code inside an isolated virtual machine and watch what it does.

## Installing

Download the `.vsix` for your platform from [Releases](https://github.com/Idris1980/lookfirst/releases) and install it:

```
code --install-extension lookfirst-win32-x64-0.4.0.vsix
```

Every file in a release is built by GitHub Actions from this repository and signed with Sigstore. Check a file before you install it:

```
gh attestation verify lookfirst-win32-x64-0.4.0.vsix --repo Idris1980/lookfirst
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
