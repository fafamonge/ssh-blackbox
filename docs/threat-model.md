# SSH Blackbox Threat Model

SSH Blackbox is designed around a strict separation of responsibilities:

- **Evidence Collection** is the trusted core.
- **Detection and Alerting** are upper layers built on top of evidence.

The core principle is:

> Evidence must survive even when alerts fail.

## Purpose

SSH Blackbox records SSH-related security events in a durable and reconstruction-friendly format, so administrators can understand what happened before, during and after an access-related incident.

## Primary Goals

- Preserve evidence of SSH access activity.
- Record authentication attempts and successful sessions.
- Track security-relevant changes related to SSH access.
- Support incident reconstruction.
- Provide a reliable evidence trail before detection logic is applied.

## Non-Goals for the Core

The evidence collection core does not try to:

- Decide whether an event is malicious.
- Block users or IP addresses.
- Replace SSH, PAM, auditd or system logs.
- Depend on alert delivery.
- Depend on detection rules.

Those functions may exist in upper layers, but they must not be required for evidence collection.

## Initial Evidence Scope

SSH Blackbox should eventually collect evidence related to:

- SSH login attempts.
- Successful SSH sessions.
- Failed authentication attempts.
- Public key authentication activity.
- Password authentication activity.
- Changes to authorized_keys files.
- Changes to sshd_config and sshd_config.d files.
- Changes to SSH-related systemd units.
- Creation or modification of local users.
- Privilege escalation paths related to SSH access.
- sudo activity related to SSH users.
- suspicious changes to root SSH access.
- timestamps useful for timeline reconstruction.

## Assumptions

SSH Blackbox assumes that:

- The server may be exposed to the public Internet.
- SSH is a critical administrative access path.
- Standard logs may be incomplete, rotated, deleted or altered.
- Root-level compromise can eventually tamper with local evidence.
- Remote or append-only evidence storage may be needed for stronger guarantees.

## Trust Boundaries

The initial local collector can improve visibility and reconstruction, but it cannot fully protect evidence against a complete root compromise on the same machine.

Future deployment modes may include:

- local-only evidence trail,
- remote collector,
- append-only storage,
- signed event chains,
- external timestamping,
- multi-node evidence replication.

## Design Principle

SSH Blackbox must collect first and interpret later.

Detection rules, alerts, dashboards and reports are useful, but they are not the foundation. The foundation is the evidence trail.
