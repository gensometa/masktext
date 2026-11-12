# masktext

An offline command-line tool for redacting sensitive information from text.
Single binary. No accounts, API keys, network requests, or runtime dependencies.
Linux/macOS · amd64/arm64 · MIT license.

[日本語ガイド](README.ja.md)

```sh
masktext -f app.log                    # app.masked.log; source stays unchanged
masktext -f app.log -o sanitized.log    # explicit destination
masktext -t 'Contact alice@example.com'
# Contact [REDACTED_EMAIL]
cat app.log | masktext                 # stdin → stdout
masktext -f app.log -o -               # file → stdout
masktext --check -f app.log --stats     # exit 1 on findings; counts only
```

## Install

Install the pinned release from [gensometa/masktext](https://github.com/gensometa/masktext):

```sh
curl -fsSL https://raw.githubusercontent.com/gensometa/masktext/v0.2.0/install.sh | sh -s -- gensometa/masktext v0.2.0
```

The installer downloads a platform-specific binary, verifies its SHA-256 checksum,
and installs to `~/.local/bin`. It needs `curl`, `tar`, and `sha256sum` or `shasum`.
No sudo or Go installation is needed. Existing masktext installations are replaced.
Review install.sh before execution when required by your environment.

```sh
export PATH="$HOME/.local/bin:$PATH"   # add to your shell profile if needed
masktext --version
```

For a different destination, set `MASKTEXT_INSTALL_DIR` on the **sh** process.
To uninstall, remove the installed `masktext` binary. To upgrade, rerun the installer
with a newer release tag (or `latest` as the script's second argument).

Build from this checkout now (Go 1.23+):

```sh
go build -trimpath -o masktext ./cmd/masktext
./masktext --help
```

## Interface

| Option | Behavior |
| --- | --- |
| `-f`, `--file FILE` | Read a UTF-8 text file; `-` means stdin |
| `-t`, `--text TEXT` | Read literal text; one positional text argument is also accepted |
| `-o`, `--output FILE` | Write a file; `-` means stdout |
| `--force` | Replace an existing output, never the input |
| `--config FILE` | Add explicit literal or Go/RE2 regex rules from JSON |
| `--phone` | Enable heuristic phone detection (10–15 digits) |
| `--check` | Detect only; emit no text and create no files |
| `--stats` | Write JSON counts, without matched values, to stderr |
| `--version` | Print version |
| `-h`, `--help` | Print help |

Place options before positional text, or use `-t` explicitly. Quote literal text.
Only one input source is allowed. An omitted input reads stdin; an interactive
terminal without an input argument prints help and exits with an error.

File input defaults to `name.masked.ext` beside the input (`app.log` →
`app.masked.log`, `archive.tar.gz` → `archive.tar.masked.gz`, `notes` →
`notes.masked`). Text and stdin default to stdout. Output directories must exist.
Existing outputs require `--force`. Input paths, hardlinks and symlink aliases
cannot be used as the output; symlink output paths are rejected.
Files are written via a temporary file in the destination directory and committed
only when complete. New output files have permissions `0600`, including with
`--force`. Disk-write failures do not truncate existing files. Standard output
cannot offer the same atomicity.

Exit status: **0** = success / check clean; **1** = check found a match;
**2** = argument, configuration, input, or output error.

```sh
masktext --check --stats -f app.log
```

Useful in CI: a match fails the step with status 1. The counts refer to merged
redaction spans rather than every overlapping detector match. Clean input emits `{}`.

## Detection scope

| Default detector | Scope |
| --- | --- |
| Email | Common ASCII email addresses |
| IP | Valid IPv4 and common IPv6 forms, including loopback/private addresses |
| Shell variables | All shell-style assignment values, including commented assignments, quotes and command substitutions |
| Shell identity and paths | `user@host`, shell prompt working directories, paths under `/root`, `/home/USER`, `/Users/USER` and `~/` |
| Discord Webhooks | Full Discord webhook URLs, including query strings |
| Credential values | Common `password`, `secret`, `api_key`, token and authorization assignments in JSON, env and log text |
| Tokens | Selected GitHub, AWS access-key ID, OpenAI-style and Slack token patterns; JWT-like strings; Bearer values |
| Private keys | PEM blocks labeled PRIVATE KEY, RSA/EC/DSA/OPENSSH/ENCRYPTED PRIVATE KEY |
| URL credentials | User information before `@` in URLs |
| Payment cards | 13–19 digits passing a Luhn checksum; no issuer verification |

Matches become `[REDACTED_EMAIL]`, `[REDACTED_SECRET]`, etc. Overlapping matches
are merged conservatively; for example, URL credentials overlapping an email
match may also redact its hostname. This is text processing, not a structured-data
parser: output is for review/sharing, and is not guaranteed to remain valid JSON,
YAML, or executable configuration. Unmatched bytes and line endings are preserved.
Masked output is not intended to be repeatedly scanned for a clean check result;
credential assignments still have sensitive-looking keys after redaction.

**Detection is heuristic. Review before sharing.** Arbitrary API keys without a
known prefix, nearby credential label or shell assignment are not reliably detected. Names,
addresses, birthdays, national IDs, business-specific secrets, Unicode/obfuscated
emails, encoded/escaped values and uncommon or multiline configuration forms
require custom rules or manual review. Shell assignments mask even nonsecret values
(such as ports); comment markers do not disable detection. Shell parsing is a
conservative text scanner, not a full Bash parser; heredocs and unusual syntax
need manual review. Ordinary public URLs outside assignments remain unchanged.
User and host detection requires a `user@host` context; standalone names are not
automatically inferred from prose. Phone detection is opt-in because it can
confuse IDs and other numbers with phones. No statistical/LLM detection is used.

UTF-8 text only, at most 32 MiB per invocation. NUL-containing/binary input and
invalid UTF-8 fail without writing output. Convert Shift_JIS or other encodings
first. PDF/Office documents, images, archives, and recursive directory processing
are not supported. The full text is held in memory, allowing multiline key matching.

## Custom rules

```json
{
  "rules": [
    { "name": "PERSON", "literal": "山田太郎" },
    { "name": "EMPLOYEE_ID", "pattern": "EMP-[0-9]{6}" }
  ]
}
```

```sh
masktext -f notes.txt --config rules.json
```

Rules extend built-in detection. Each rule needs exactly one `literal` or `pattern`.
Names use uppercase letters, numbers and underscores, starting with a letter
(max 40 characters). Patterns use Go's RE2-style syntax; lookaround and
backreferences are unsupported. The entire regex match is redacted. Patterns
matching empty input are rejected. Treat rule files as sensitive if they contain
real names or literal secrets; keep them outside the public repository.
See [rules.example.json](rules.example.json) for synthetic examples.

## Privacy

Use file or stdin input for real secrets: `-t` and positional text can appear in
shell history and process listings. Commands in this README use synthetic data.
The runtime is offline and logs no matched values. Errors omit input fragments and
paths. `--stats` reports only categories and counts. The installer uses the network.
Redaction cannot revoke exposed credentials or remove originals from history,
backups or logs. See [SECURITY.md](SECURITY.md).

## Release process

1. Choose an available repository/tool name; the name `masktext` is provisional
   and has not been checked for trademark or package-name availability.
2. Update the install examples for your fork and review the MIT copyright line.
3. Create a public GitHub repository and push this source. Enable Actions and
   private vulnerability reporting. Keep real samples and rule files out of Git.
4. Run `go test -race ./...` and `go vet ./...` and let Linux/macOS CI pass.
5. Push tag `v0.2.0`. The release workflow tests the code, builds four archives,
   produces `SHA256SUMS`, and publishes a GitHub Release.
6. Test the pinned install command on Linux and macOS. Tag each subsequent release;
   keep CLI changes backward compatible and document detector behavior changes.

CI runs on Linux and macOS for each push and pull request. Release workflows
run when a version tag is pushed. Test the published installer after each release.

[Contributing](CONTRIBUTING.md) · [MIT license](LICENSE)
