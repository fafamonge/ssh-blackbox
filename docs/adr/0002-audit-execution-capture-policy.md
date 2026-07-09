# ADR 0002: Audit execution capture policy

## Status

Accepted.

## Context

SSH Blackbox requires enough execution evidence to reconstruct important
administrative activity without attempting exhaustive host surveillance.

An initial auditd rule captured every execve where euid=0. Real-host testing
showed that this generated excessive evidence from normal system activity,
automation, development tools, and direct root activity.

## Decision

Capture privileged execution when the original audit identity belongs to an
attributable non-root login user:

    execve
    euid=0
    auid>=1000
    auid!=unset

The current audit key is:

    root_exec_user

Critical filesystem and configuration changes remain captured independently
using audit watches.

Direct root SSH access is recorded through OpenSSH evidence and audit login
evidence. SSH Blackbox does not globally capture every execve from auid=0.

## Rejected alternatives

- Capture every root execve.
- Filter by executable name.
- Filter only by TTY.
- Discard incomplete evidence.

## Principle

Capture policy and correlation policy are separate.

Absence of a conservative link does not mean absence of evidence.
