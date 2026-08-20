# codeql-demo-vulnerable

Intentionally vulnerable sample app for testing GitHub Advanced Security
(GHAS) CodeQL code scanning and repository rulesets that block merging PRs
with critical findings.

**This code is deliberately insecure. Do not deploy it, and do not copy these
patterns into real projects.**

## What's in here

[`app.py`](app.py) is a small Flask app with four flaws CodeQL's default
`security-and-quality` query suite flags at critical/error severity:

| Route       | Flaw                    | CodeQL query                  |
|-------------|-------------------------|--------------------------------|
| `/users`    | SQL injection           | `py/sql-injection`             |
| `/ping`     | Command injection       | `py/command-line-injection`    |
| `/backup`   | Command injection (shell=True) | `py/command-line-injection` |
| `/eval`     | Code injection (`eval`) | `py/code-injection`            |

[`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) runs CodeQL
analysis on every push and pull request against `main` ("advanced setup").
Note: a checked-in workflow like this takes precedence over and disables
GitHub's org-managed "default setup" for this repo — the two can't run
side by side.

## Setting up the repo and merge-blocking ruleset

See the setup walkthrough provided alongside this project (repo creation,
enabling code scanning, and configuring a ruleset that blocks merges on
critical CodeQL alerts).
