# SSH Blackbox Evidence Model

SSH Blackbox is evidence-first.

The purpose of the evidence model is to define what must be captured, how events should be represented, and how those events can later be used for incident reconstruction, detection, alerting and forensic review.

## Core Principle

> Evidence is collected before interpretation.

SSH Blackbox must preserve facts first. Detection rules, severity levels, classifications and alerts are derived later.

## Evidence Event

An evidence event is a structured record of something security-relevant observed on the system.

Each event should be:

* timestamped,
* source-identified,
* host-identified,
* append-friendly,
* reconstruction-friendly,
* safe to process later,
* suitable for signing or chaining in future versions.

## Minimum Event Fields

Every event should eventually include:

```json
{
  "schema_version": "0.1",
  "event_id": "unique-event-id",
  "event_type": "ssh.auth.failed",
  "timestamp": "2026-07-07T00:00:00Z",
  "hostname": "server.example.com",
  "node_id": "server-01",
  "source": "secure_log",
  "severity": "info",
  "actor": {},
  "target": {},
  "context": {},
  "raw": {}
}
```

## Event Categories

Initial event categories:

* `ssh.auth.failed`
* `ssh.auth.success`
* `ssh.session.opened`
* `ssh.session.closed`
* `ssh.key.added`
* `ssh.key.removed`
* `ssh.config.changed`
* `user.created`
* `user.modified`
* `privilege.sudo`
* `system.sshd.changed`
* `system.identity.changed`

## Actor

The actor represents the entity attempting or performing access.

Possible fields:

```json
{
  "ip": "192.0.2.10",
  "port": 55124,
  "username": "root",
  "auth_method": "publickey"
}
```

## Target

The target represents the local account, file, service or component affected by the event.

Possible fields:

```json
{
  "user": "root",
  "file": "/root/.ssh/authorized_keys",
  "service": "sshd"
}
```

## Context

Context contains structured metadata useful for reconstruction.

Examples:

```json
{
  "pid": 12345,
  "process": "sshd",
  "tty": "pts/0",
  "session_id": "optional-session-id",
  "result": "failed",
  "reason": "invalid_user"
}
```

## Raw Evidence

The `raw` field may contain the original parsed line, command output, file hash, inode metadata, audit record or other source-specific information.

Raw data must be handled carefully. It may include sensitive information and should not be committed to public repositories.

## Evidence Sources

Initial possible sources:

* `/var/log/secure`
* `/var/log/auth.log`
* `journalctl -u sshd`
* `journalctl -u ssh`
* `auditd`
* filesystem metadata
* file hashes
* authorized_keys snapshots
* sshd configuration snapshots

## Integrity Roadmap

Future versions may support:

* append-only local event logs,
* hash chaining,
* event signatures,
* remote evidence collectors,
* external timestamping,
* tamper detection,
* immutable object storage,
* multi-node evidence replication.

## Design Boundary

The evidence model should remain stable even if detection rules change.

Detection may evolve quickly. Evidence format should evolve carefully.

