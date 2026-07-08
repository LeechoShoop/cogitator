# Security

Cogitator is a TLS-intercepting proxy and pentest toolkit. By design it
handles other systems' traffic, credentials, and a CA private key capable of
impersonating any HTTPS host to anyone who trusts it. This document is a
threat model for the tool itself — what it stores, what trust it grants, and
what's explicitly out of scope — not a report template for findings *made
with* Cogitator.

## 1. What Cogitator stores locally, and where

Everything below lives in the working directory Cogitator is run from, as
plain files on disk. There is no remote storage or telemetry.

| File | Contents | At rest |
|---|---|---|
| `cogitator_last.cogitator` (auto-saved on exit) | Scope rules, **full request/response history** (headers + bodies, capped), scanner findings, repeater tabs/history | **Plaintext JSON** |
| `*.cogitator` (explicit `Workspace-Save`) | Same as above | Plaintext, or AES-256-GCM/Argon2id if saved via the encrypted path |
| `cogitator_sessions.vault` | Named session profiles: cookies and custom headers (e.g. `Authorization: Bearer …`) used to replay authenticated requests | Always encrypted (AES-256-GCM, Argon2id-derived key) |
| `cogitator_ca.key` | The local CA's private key | Plaintext by default; PKCS#8-encrypted (scrypt + AES-256-CBC) if a passphrase was set at CA generation |
| `cogitator_ca.pem` | The local CA's public certificate | Plaintext — meant to be imported into a trust store |
| `cogitator.log` | Structured JSON event log: methods, hosts, status codes, errors, timings | Plaintext; `Authorization`/`Cookie`/`Set-Cookie`/`X-Api-Key` values are redacted before being written, as defense in depth |
| `{domain}_proxy_report.txt` | Per-host analysis report (cookie/HSTS grading, etc.), written on every proxied request | Plaintext |

**The single biggest exposure**: the auto-save that runs on every exit writes
the entire captured traffic history — including any `Authorization` headers,
`Cookie` values, and request/response bodies that passed through the proxy —
to `cogitator_last.cogitator` **unencrypted**. Anyone who can read that file
(another local user, a backup, a synced folder, a stolen laptop) can read
every credential and body Cogitator captured in that session. If you're
testing anything with real credentials, use `Workspace-Save` with a
passphrase and don't rely on the auto-save file, or run Cogitator on a
machine/disk you already treat as sensitive.

## 2. What the local CA grants, and the blast radius if it's stolen

`cogitator_ca.pem` is a self-signed root CA (ECDSA P-256) generated on first
run. To do TLS interception without certificate warnings, you import it into
a browser's or OS's trust store — at which point **that device will silently
trust any certificate signed by `cogitator_ca.key`**, not just ones Cogitator
itself generates.

If `cogitator_ca.key` is stolen (plaintext, or decrypted at the point of
theft), the holder can mint a valid-looking certificate for *any* hostname
and MITM *any* HTTPS traffic on *any* device that has that CA in its trust
store — indefinitely, until the CA is removed from every such trust store.
This is a capability independent of Cogitator continuing to run; it's a
property of the key itself.

Practical implications:
- Treat `cogitator_ca.key` as a secret on par with an SSH/code-signing key,
  not an application config file. Set a passphrase for it.
- Import the CA into scoped, disposable trust anchors (a dedicated browser
  profile, a test VM, a throwaway device) rather than your daily-driver
  machine's system-wide trust store.
- Remove the CA from any trust store once you're done testing. A CA sitting
  trusted-but-unused on a device is pure downside.
- If the key is ever suspected compromised, its blast radius is every device
  that still trusts it — rotate by regenerating the CA and re-importing
  everywhere, and assume traffic on old trusting devices may have been
  intercepted in the meantime.

## 3. Scope: authorized testing only

Cogitator is built for testing systems you own, or have explicit written
authorization to test. It has no built-in mechanism to verify authorization
or consent — that responsibility sits entirely with the operator.

Explicitly out of scope for this tool's threat model:
- Protecting a target system from Cogitator — that's the point of the tool.
- Verifying you're allowed to intercept the traffic in front of you.
  Intercepting or scanning systems without authorization is the operator's
  legal exposure (and, depending on jurisdiction, may be criminal), not a
  Cogitator safety feature to be added later.
- Protecting Cogitator's own data (workspace/session/CA files, per §1) from
  someone who already has local access to the machine it runs on. Local
  access to a testing machine is treated as equivalent to local access to any
  other secrets-bearing tool: game over for anything unencrypted on it.
- Safety of intercepting third-party or production traffic incidentally
  captured by a broad proxy scope. Use `Scope-Include`/`Scope-Exclude`
  deliberately.

If you're not sure whether you're authorized to point Cogitator at
something, you aren't — don't.

## 4. Reporting a vulnerability in Cogitator itself

This section is for bugs in Cogitator's own code (e.g. a way to leak the CA
key, bypass the redaction in §1, corrupt a vault file into decrypting with
the wrong passphrase, or a memory-safety issue in the proxy path) — not for
findings you make while *using* Cogitator against a target.

- **Contact**: `<security contact — fill in an email or GitHub handle you
  monitor>`.
- Please don't open a public GitHub issue for security reports — email/DM
  first so a fix can land before the issue is public.
- Include the version/commit, a minimal repro, and what you think the impact
  is (e.g. "leaks the CA key passphrase into cogitator.log").
- This is currently a solo project maintained on a best-effort basis: there's
  no formal SLA, but reports will be acknowledged and a fix or mitigation
  will be prioritized over other work.
- Please give a reasonable window to fix the issue before any public
  disclosure.