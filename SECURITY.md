# Security Policy

## Report A Vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Vel-Labs/orcastrata-max/security/advisories/new).

Do not open a public issue for a suspected vulnerability. Do not include
credentials, tokens, private keys, private configuration, or private task
content.

Include the affected version, a sanitized reproduction, expected behavior, and
the observed impact.

## Security Model

Orcastrata Max does not store provider credentials or automate provider login.
Provider authentication remains inside the configured provider tool. Task
grants, not model identity, control read and write authority. Exact tool/model
requests fail closed on identity mismatch.

Supported versions and response commitments will be listed in published release
notes. Pre-publication source candidates have no public support commitment.

