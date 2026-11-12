# Security policy

masktext is an offline heuristic redactor, not a guarantee of anonymization.
Review output before sharing it. Detection has false positives and false negatives.

Do not post real secrets, personal data, or private input files in public issues.
Use synthetic reproductions. Report vulnerabilities privately at
https://github.com/gensometa/masktext/security/advisories/new.
Public issues must contain synthetic examples only.

If a credential was exposed, revoke and rotate it. Redacting a later copy does not
remove it from Git history, shell history, logs, backups, or previously shared files.

The runtime sends no network requests, writes no telemetry, and never logs matched
values. Input and output exist in memory; secure memory erasure is not implemented.
Output uses mode 0600. Parent-directory access and stdout capture remain the user's
responsibility. Use trusted directories: filesystem races involving hostile concurrent
directory manipulation are outside the threat model.

The installer accesses GitHub and checks archive SHA-256 integrity against checksums
from the same release. This does not independently authenticate a compromised release.
Install only from a repository and release you trust. Pin a version for repeatability.
