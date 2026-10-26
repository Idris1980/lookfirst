# LookFirst on GitHub

When people work together on GitHub, changes are proposed as *pull requests*. Add LookFirst to a repository, and every pull request is checked automatically:

- problems are marked on the changed lines, where the reviewer reads the code
- a summary comment is added, and kept up to date when more changes are pushed
- the full report with pictures can be downloaded from the run
- if you want, a pull request with a serious problem can be stopped

## Adding it

Create the file `.github/workflows/lookfirst.yml` in your repository:

```yaml
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
      - uses: Idris1980/lookfirst@v0.12.0
        with:
          path: .          # files or folders, separated by spaces
          fail-on: high    # or medium, low, none
```

## How it behaves

- **It looks at the change.** Only the files a pull request changes get markings on their lines, the comment starts with their findings, and `fail-on` only counts them. Old problems elsewhere in the repository neither crowd out the new ones nor block the change. Everything else that was read is folded away in the comment and is in the full report.
- **It builds LookFirst from the source** of the version you name, so what runs is exactly the code in this repository.
- **It needs no secrets.** In pull requests from forks GitHub gives a read-only token: the lines are still marked, only the comment is skipped.

## Outputs

`high`, `medium` and `low` give the number of findings of each severity, for later steps in the same job.
