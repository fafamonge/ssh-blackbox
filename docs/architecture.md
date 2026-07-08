# SSH Blackbox Architecture

SSH Blackbox follows an evidence-first architecture.

The system is divided into two major responsibility domains:

1. Evidence Core
2. Detection and Alerting Layer

The Evidence Core is the trusted foundation of the system. Detection and alerting consume evidence but must never be required for evidence collection.

## Architectural Principle

> Collection must continue independently of detection and alert delivery.

A failure in a detection rule, notification provider, remote endpoint or analysis component must not stop the collection of evidence.

## High-Level Flow

SSH and system activity is observed through supported evidence sources.

The initial processing flow is:

Evidence Sources
→ Collection
→ Parsing
→ Normalization
→ Event Identification
→ Local Evidence Store
→ Detection
→ Alerting

Future versions may additionally export evidence to remote collectors or replicated evidence stores.

## 1. Evidence Sources

Evidence Sources are operating system facilities and security-relevant files from which SSH Blackbox obtains observable facts.

Initial sources may include:

* systemd journal,
* `/var/log/secure`,
* `/var/log/auth.log`,
* SSH configuration files,
* authorized_keys files,
* local account databases and metadata,
* selected filesystem metadata,
* auditd events where available.

The architecture must not assume that every Linux distribution exposes the same sources.

Source adapters should isolate platform-specific differences from the internal evidence model.

## 2. Evidence Collector

The Evidence Collector reads supported sources and forwards observations to the processing pipeline.

Its responsibilities are:

* observe new source events,
* preserve source identity,
* maintain collection position where required,
* avoid unnecessary duplication,
* recover cleanly after restart,
* send observations for parsing and normalization.

The collector should remain small and operationally predictable.

## 3. Parser Layer

Parsers convert source-specific observations into structured data.

A parser understands the syntax of a particular source but should not decide whether an event is malicious.

Examples include:

* OpenSSH authentication parser,
* systemd journal parser,
* secure/auth.log parser,
* authorized_keys change parser,
* SSH configuration change parser.

Parsing and detection are separate responsibilities.

## 4. Normalization Layer

The Normalization Layer converts parsed observations into the SSH Blackbox Evidence Model.

Normalized events use stable fields and event categories regardless of the original source.

For example, a failed SSH authentication observed through journald and the same type of event observed through `/var/log/secure` should produce compatible normalized evidence events.

Normalization enables later detection logic to operate independently of the original operating system log format.

## 5. Event Identification

Every accepted evidence event receives a unique event identifier.

The event identity mechanism must support:

* local uniqueness,
* safe merging from multiple nodes,
* chronological reconstruction,
* future integrity verification.

The exact identifier strategy will be selected during implementation.

## 6. Local Evidence Store

The initial implementation will be local-first.

The first storage format is expected to be append-oriented JSON Lines (JSONL), with one normalized event per line.

The storage layer must prioritize:

* simple recovery,
* sequential writing,
* human inspectability,
* machine processing,
* controlled rotation,
* future integrity extensions.

The initial local evidence store does not claim to be immutable against complete root compromise.

That limitation must remain explicit.

## 7. Detection Layer

The Detection Layer consumes normalized evidence.

It is not part of the trusted evidence collection path.

Its responsibilities may include:

* matching individual event rules,
* detecting repeated failures,
* identifying unusual authentication patterns,
* detecting changes to SSH trust material,
* correlating related events,
* assigning detection severity,
* generating findings.

Detection failures must not interrupt evidence collection.

## 8. Alerting Layer

The Alerting Layer consumes findings produced by detection.

Future notification providers may include:

* email,
* webhook,
* messaging platforms,
* SIEM integrations,
* external incident management systems.

Alert delivery failures must not affect evidence collection or evidence storage.

## 9. State

SSH Blackbox may require small amounts of operational state, such as:

* source cursor positions,
* last processed journal cursor,
* file observation metadata,
* deduplication state,
* collector health information.

Operational state is not evidence.

State may be recreated or lost without invalidating evidence already collected.

This distinction must remain explicit in the implementation.

## 10. Trust Boundaries

The initial local deployment has an unavoidable trust boundary:

A process with complete root control of the monitored server may eventually alter the collector, evidence files, configuration or system clock.

SSH Blackbox should improve evidence quality and incident reconstruction without making false claims about local immutability.

Stronger future deployment models may include:

* remote evidence forwarding,
* signed event chains,
* hash-linked evidence,
* external timestamping,
* write-restricted collectors,
* immutable object storage,
* multi-node evidence replication.

## 11. Failure Isolation

The architecture should isolate failures between components.

The following failures must not stop the Evidence Core:

* malformed detection rules,
* alert provider failure,
* network outage,
* remote collector outage,
* dashboard outage,
* reporting failure.

The core objective remains continuous evidence collection.

## MVP Architecture

The first implementation milestone should remain intentionally small.

The MVP should provide:

* one supported Linux platform family for initial validation,
* journald and/or secure log collection,
* OpenSSH authentication event parsing,
* normalized evidence events,
* append-oriented local JSONL storage,
* persistent source position,
* service execution under systemd,
* basic collector health status,
* controlled test fixtures with no real private evidence.

The MVP should not attempt to implement every future integrity, remote collection or detection capability at once.

## Architectural Direction

SSH Blackbox should evolve from a reliable local evidence recorder into a distributed forensic telemetry system without sacrificing the simplicity and reliability of its Evidence Core.

Evidence comes first.

Detection interprets evidence.

Alerting communicates findings.

Each layer depends on the layer below it, but the Evidence Core must never depend on the layers above it.

