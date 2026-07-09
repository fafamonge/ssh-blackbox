# SSH Blackbox

SSH Blackbox is an independent, evidence-first security telemetry and forensic audit system for SSH infrastructure.

Its purpose is to help operators answer practical incident-response questions quickly:

* Who authenticated to the server?
* From which remote address?
* Which authentication method was used?
* Which audit session belongs to the observed SSH access?
* Did the original actor execute commands as root?
* Which executables were observed?
* Were security-critical files changed?
* Which critical evidence can be conservatively linked to an SSH session?
* Which critical evidence exists but cannot be safely attributed to a linked SSH session?

SSH Blackbox prioritizes observable evidence and conservative correlation over speculative attribution.

## Current Capabilities

The current implementation provides:

* OpenSSH secure log parsing,
* auditd event parsing,
* normalized evidence events,
* SSH session construction,
* audit session correlation,
* audit record grouping by audit serial,
* reconstruction of security-critical file changes,
* conservative linking between SSH and audit sessions,
* evidence-set JSON output,
* human-readable forensic reconstruction,
* preservation of critical evidence that cannot be linked to an SSH session,
* fixture-based integration and full-chain tests.

## Evidence Model

SSH Blackbox separates three concepts that must not be confused.

### Observed Evidence

Facts directly represented by supported evidence sources.

Examples:

* an accepted SSH public key authentication,
* an SSH session opening,
* an audit login event,
* an audited process execution,
* an audited access to a protected path.

### Conservative Correlation

Events may be linked when available evidence provides a sufficiently strong basis.

Current linking can use evidence such as:

* original actor identity,
* remote address.

A link records its basis explicitly.

### Unlinked Critical Evidence

A critical change may be real and relevant even when it cannot be conservatively linked to a specific SSH session.

SSH Blackbox preserves and reports that evidence without inventing attribution.

The absence of a safe correlation does not erase observed evidence.

## Processing Pipeline

The implemented forensic processing path is:

```text
OpenSSH logs
    |
    v
OpenSSH parser
    |
    v
SSH session builder
    |
    +-------------------------+
                              |
auditd records                |
    |                         |
    v                         |
auditd parser                 |
    |                         |
    v                         |
audit serial grouping         |
    |                         |
    +--> audit sessions ------+
    |                         |
    +--> critical changes     |
                              v
                    conservative linking
                              |
                              v
                       reconstruction
                         /          \
                        v            v
              linked evidence    unlinked critical
              reconstruction     evidence preservation
```

## CLI

### Version

```bash
ssh-blackbox version
```

### Status

```bash
ssh-blackbox status
```

### Parse OpenSSH Evidence

```bash
ssh-blackbox parse --file <secure.log>
```

### Parse auditd Evidence

```bash
ssh-blackbox parse-audit --file <audit.log>
```

### Build an Evidence Set

```bash
ssh-blackbox evidence-set \
  --ssh-file <secure.log> \
  --audit-file <audit.log>
```

The evidence set can contain:

* SSH sessions,
* audit sessions,
* conservative evidence links,
* reconstructed critical changes.

### Reconstruct Activity

```bash
ssh-blackbox reconstruct \
  --ssh-file <secure.log> \
  --audit-file <audit.log>
```

For linked evidence, reconstruction can show:

* SSH actor,
* remote address and port,
* authentication method,
* linked audit session,
* original actor,
* effective users,
* terminals,
* recorded executions,
* critical file changes,
* evidence-link basis.

Critical evidence that cannot be safely linked is reported separately as:

```text
UNLINKED CRITICAL EVIDENCE
```

This section deliberately does not claim that the activity belongs to a specific SSH session.

## Example Reconstruction

```text
SSH SESSION
Actor:        wagner
Remote:       190.5.138.94:62133
Auth:         publickey
Opened:       Jul  8 18:00:28

LINKED AUDIT SESSION
Audit session: 16695
Original actor: wagner
Effective users: root
Terminals:      /dev/pts/4, pts5

RECORDED EXECUTIONS
...

CRITICAL FILE CHANGES
...

LINK BASIS
- actor_identity_match
- remote_address_match
```

## Audit Capture Policy

SSH Blackbox uses a conservative audit capture policy.

The objective is not exhaustive recording of every root process on a server. The objective is to retain evidence that is operationally useful for identifying important SSH-related failures, privilege transitions and security-critical changes without generating unnecessary audit noise.

The current capture policy is documented in:

```text
docs/adr/0002-audit-execution-capture-policy.md
```

## Current Scope

SSH Blackbox is under active development.

The current implementation focuses on the forensic evidence path. Collection daemons, persistent local evidence storage, detection rules, alert delivery and distributed evidence replication remain separate architectural stages and should not be confused with capabilities already implemented.

## Design Principle

Evidence comes first.

Correlation must explain its basis.

Missing correlation must not erase evidence.

SSH Blackbox should help operators reconstruct important incidents quickly without pretending to know more than the available evidence demonstrates.
