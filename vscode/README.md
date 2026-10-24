# LookFirst: See What Code Does Before You Run It

Copied some code from an AI assistant or a forum and not sure what it does? LookFirst reads it and shows you, before you run it:

- **A picture** of what it would build or touch: servers, firewalls, databases, containers, websites it talks to, files on your computer, programs it starts and packages it pulls in.
- **The risks in plain English**: ports open to the whole internet, passwords written in the code, scripts that download and run more code, files that start automatically, and more.
- **Where in the code** each risk is, as squiggles and in the Problems panel.

## How to use it

- Right-click a file or folder and choose **Show in LookFirst**.
- Click a box in the picture, or a place in the list of findings, to jump straight to that line in the code.
- Or just save, or paste a larger piece of code. LookFirst checks it on its own and warns you if something is serious.

## What it reads

Terraform, Bicep and ARM templates, docker-compose, Kubernetes manifests, Dockerfiles, Python, JavaScript and TypeScript, shell scripts, PowerShell, package.json and requirements.txt. A folder with several projects gets one picture per project, the riskiest first.

## Safe by design

- **Your code is never run.** It is only read as text. To catch syntax errors, the language's own parser is asked to read the file (for example `node --check`), and that never runs it either.
- **Nothing leaves your computer.** The extension makes no network requests. The picture is a plain HTML page with no scripts, shown with scripts switched off.
- **A workspace cannot change which program runs.** The `lookFirst.path` setting can only be set in your own user settings.

LookFirst tells you what it found. It cannot promise that code is safe: code that is written to hide what it does can get past any reader.

## Settings

| Setting | Default | What it does |
| --- | --- | --- |
| `lookFirst.checkOnSave` | `true` | Check supported files when you save them. |
| `lookFirst.checkOnPaste` | `true` | Check right after a larger piece of code is pasted or inserted. |
| `lookFirst.pasteMinLines` | `5` | How many lines an insertion needs before it is checked. |
| `lookFirst.path` | (bundled) | Use another lookfirst program. User settings only. |
