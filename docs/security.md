# How LookFirst keeps you safe

LookFirst is a security tool, so it has to be careful itself. This page explains how, in technical detail.

## Your code is never run

The code is read as text. Syntax checks ask the language's own parser to read the file (`node --check`, `bash -n`, Python's `ast.parse`, the PowerShell parser), which never runs it. Bicep is compiled locally with `--no-restore`, so no modules are downloaded.

## Nothing is sent anywhere, with two opt-in exceptions

The program makes no network requests. The exceptions are:

- **The AI explanation in VS Code**, which is off until you turn it on and shows you what it will send every time. Only about 30 lines around the problem are sent.
- **`lookfirst try`**, which sends a template to your own Azure subscription when you ask it to (see [compare-with-azure.md](compare-with-azure.md)).

The web page runs the reader in your browser and may only load its own files, so there is nowhere your code could be sent.

## Secrets are masked before anything goes to an AI

Known key formats, values of settings named like passwords (also when the name is on the line before, as in Kubernetes `- name: DB_PASSWORD` / `value: …`), multi-line private keys and long random strings are replaced with `«SECRET_1»` and so on. The real values never leave your computer; they are put back into a suggested fix only there. The tests mask every example file and check that LookFirst finds no secret left in them.

## The report cannot run anything

The report is a plain HTML page with a Content-Security-Policy that forbids scripts and network access, and everything from the checked code is escaped. In VS Code it is shown with scripts switched off; its links can only open files that are part of the report, or ask the AI (which asks you first). The AI's answer is shown as plain text, never as code that runs. On GitHub, text from the checked code is escaped so a pull request cannot add commands to the run or links and images to the comment.

## A downloaded repository cannot change how the extension behaves

The program the extension runs and all AI settings can only be set in your own user settings, so a repository you open cannot turn on the AI, stop it from asking, choose where your code is sent, or run another program. An Anthropic API key, if you use one, is stored encrypted in VS Code's secret storage, never in settings or files.

## Inputs are limited

Files over 2 MB and folders with more than 500 files are not read, and symbolic links are not followed.

## Checking a download

Every file in a [release](https://github.com/Idris1980/lookfirst/releases) is built by GitHub Actions from this repository and signed with Sigstore. Check one before you install it with the [GitHub CLI](https://cli.github.com/):

```
gh attestation verify lookfirst-win32-x64-0.8.0.vsix --repo Idris1980/lookfirst
```

It should say `Verification succeeded`. Each release also has `SHA256SUMS.txt` and a software bill of materials (`lookfirst.spdx.json`) listing everything the program is built from.

## Reporting a problem

If you find a way around any of this, please open an issue on GitHub.
