# SSH Blackbox Implementation Decisions

This document records key implementation decisions for SSH Blackbox.

The goal is to keep architectural reasoning visible, intentional and easy to review as the project evolves.

## Decision 001: Evidence Core Language

### Status

Accepted.

### Decision

The SSH Blackbox Evidence Core will be implemented in Go.

### Reasoning

The Evidence Core is expected to run as a long-lived system service on Linux servers. It should be predictable, lightweight and easy to deploy.

Go is a good fit because it provides:

- a single static or mostly self-contained binary,
- no required external runtime such as Python or Node.js,
- strong support for long-running services,
- good concurrency primitives,
- good standard library support for JSON, files, signals and networking,
- easy deployment under systemd,
- good long-term maintainability,
- broad Linux support.

### Scope

Go will be used for:

- the evidence collector,
- event normalization,
- local JSONL evidence writing,
- source cursor/state handling,
- collector health reporting,
- future remote forwarding.

### Non-Core Tooling

Bash may be used for:

- installation scripts,
- uninstallation scripts,
- environment checks,
- systemd helper scripts,
- packaging helpers.

Python may be used later for:

- offline analysis,
- reporting tools,
- test data generation,
- developer utilities.

### Design Constraint

The Evidence Core must remain small, reliable and independent from detection and alerting logic.

Detection and alerting may be implemented in Go or other languages later, but they must not be required for evidence collection.
