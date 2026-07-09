# SSH Blackbox Architecture

SSH Blackbox follows an evidence-first architecture.

The system is designed to collect, normalize, correlate and reconstruct security-relevant SSH activity while preserving a strict distinction between observed evidence and inferred relationships.

## Architectural Principles

### Evidence Comes First

Evidence collection and evidence interpretation are separate responsibilities.

A parser records what a source says. It does not decide whether activity is malicious.

A correlation component may establish a relationship only when supported by explicit evidence.

A reconstruction presents linked evidence but must not invent missing events or attribution.

### Missing Correlation Does Not Erase Evidence

A security-critical change may be observed even when SSH Blackbox cannot conservatively associate it with a specific SSH session.

Such evidence must remain visible as unlinked critical evidence.

### Correlation Must Explain Its Basis

Evidence links record the reasons that support them.

Examples include:

* actor identity match,
* remote address match.

The architecture favors explainable conservative links over opaque confidence scores or speculative attribution.

### Collection Must Remain Independent

The long-term architecture separates the Evidence Core from detection and alerting.

A failure in:

* a detection rule,
* an alert provider,
* a remote endpoint,
* a dashboard,
* an analysis component,

must not prevent evidence collection.

## Implemented Processing Architecture

The current implementation provides the following processing path:

```text
                         +------------------+
                         |  OpenSSH logs    |
                         +--------+---------+
                                  |
                                  v
                         +------------------+
                         | OpenSSH parser   |
                         +--------+---------+
                                  |
                                  v
                         +------------------+
                         | SSH sessions     |
                         +--------+---------+
                                  |
                                  |
                                  v
+------------------+     +------------------+
| auditd records   |     | conservative     |
+--------+---------+     | evidence linking |
         |               +--------+---------+
         v                        ^
+------------------+              |
| auditd parser    |              |
+--------+---------+              |
         |                        |
         v                        |
+------------------+              |
| audit records    |              |
| grouped by       |              |
| audit serial     |              |
+--------+---------+              |
         |                        |
         +-------------+----------+
                       |
             +---------+---------+
             |                   |
             v                   v
    +----------------+   +------------------+
    | audit sessions |   | critical changes |
    +----------------+   +--------+---------+
                                  |
                                  v
                         +------------------+
                         | reconstruction   |
                         +--------+---------+
                                  |
                     +------------+------------+
                     |                         |
                     v                         v
          +---------------------+   +---------------------+
          | linked forensic     |   | unlinked critical   |
          | reconstruction      |   | evidence            |
          +---------------------+   +---------------------+
```

## 1. Evidence Sources

Evidence sources are operating system facilities and security-relevant records from which SSH Blackbox obtains observable facts.

Currently implemented parsing paths include:

* OpenSSH secure-style logs,
* auditd records.

The architecture may later support additional source adapters such as:

* systemd journal,
* distribution-specific authentication logs,
* additional filesystem evidence,
* external or replicated evidence feeds.

The architecture must not assume that every Linux distribution exposes identical sources.

## 2. Parser Layer

Parsers convert source-specific records into normalized evidence events.

Current parser packages include:

* OpenSSH parsing,
* auditd parsing.

A parser is responsible for syntax and source interpretation.

A parser must not:

* classify an actor as malicious,
* invent a missing session,
* claim that two independent records belong together without evidence,
* discard a critical observation merely because later correlation is unavailable.

## 3. Normalized Evidence

Source observations are converted into the SSH Blackbox evidence model.

Normalized events preserve information such as:

* event type,
* source,
* hostname,
* raw timestamp,
* normalized timestamp where available,
* process identifier,
* actor attributes,
* contextual attributes,
* original raw evidence.

Normalization allows later components to operate without depending directly on source log syntax.

## 4. SSH Session Construction

OpenSSH events are grouped into SSH session representations.

A session may include:

* session identifier,
* username,
* remote IP address,
* remote port,
* sshd process identifier,
* start and end observations,
* normalized timestamps,
* authentication method,
* source events.

Session construction organizes related OpenSSH evidence. It does not by itself establish a relationship with auditd activity.

## 5. Audit Record Grouping

auditd frequently represents one logical audited operation using multiple records that share the same audit serial.

SSH Blackbox groups audit evidence by serial before reconstructing higher-level facts.

This is required because information about one operation may be distributed across records such as:

* SYSCALL,
* PATH,
* USER_LOGIN,
* related audit record types.

The grouped audit record is an intermediate evidence structure.

## 6. Audit Session Correlation

Normalized audit events are summarized into audit sessions using audit session identifiers and available actor context.

An audit session may summarize:

* audit session ID,
* original audit user,
* remote address,
* terminals,
* effective users,
* executables,
* process IDs,
* parent process IDs,
* audit keys,
* session bounds,
* root execution observations.

The original actor and the effective user are distinct concepts.

For example, activity may retain:

```text
original actor: wagner
effective user: root
```

This distinction is essential for reconstructing privilege transitions.

## 7. Critical Change Reconstruction

Grouped audit records are analyzed for changes to security-critical paths.

A reconstructed critical change may contain:

* audit serial,
* audit session,
* original actor,
* effective user,
* executable,
* command,
* process ID,
* parent process ID,
* terminal,
* affected paths,
* audit keys.

Critical changes are evidence objects independent of whether they can later be linked to an SSH session.

## 8. Conservative Evidence Linking

The linking layer associates SSH sessions with audit sessions only when available evidence satisfies supported conservative criteria.

Current link reasons include:

* `actor_identity_match`,
* `remote_address_match`.

The link itself records its reasons.

The architecture deliberately avoids treating temporal proximity alone as proof of identity.

Future linking rules may be added, but they must remain:

* explainable,
* testable,
* evidence-based,
* conservative.

## 9. Forensic Reconstruction

The reconstruction layer combines:

* SSH sessions,
* audit sessions,
* evidence links,
* critical changes.

A linked reconstruction can present:

* SSH actor,
* remote endpoint,
* authentication method,
* linked audit session,
* original actor,
* effective users,
* terminals,
* recorded executions,
* critical file changes,
* link basis.

The reconstruction layer must not claim facts that are absent from the underlying evidence.

## 10. Unlinked Critical Evidence

Critical evidence is preserved even when no supported SSH-to-audit link exists.

This evidence is reported separately as:

```text
UNLINKED CRITICAL EVIDENCE
```

The distinction is intentional.

An unlinked critical change means:

* the critical evidence was observed,
* the available processing path reconstructed the change,
* no supported conservative link associated it with a reconstructed SSH session.

It does not mean:

* the change was necessarily caused through SSH,
* the actor is unknown if auditd recorded an original actor,
* the event is malicious,
* the system should infer a missing SSH session.

## 11. Evidence Set

The evidence-set output provides a machine-readable representation of reconstructed evidence.

It may include:

* SSH sessions,
* audit sessions,
* evidence links,
* critical changes.

This representation is intended to support later analysis, storage, reporting and detection components without forcing those concerns into the parser layer.

## 12. Human-Readable Reconstruction

The reconstruction text output is designed for rapid operational incident review.

Its purpose is to answer important questions quickly without requiring an operator to manually join raw OpenSSH and auditd records.

The text representation is a view over evidence and correlations. It is not a replacement for the underlying evidence.

## 13. Trust Boundaries

The initial local deployment has an unavoidable trust boundary.

A process with complete root control of the monitored server may eventually alter:

* the collector,
* evidence files,
* configuration,
* audit configuration,
* the system clock.

SSH Blackbox improves evidence quality and incident reconstruction but does not claim local immutability against complete root compromise.

Future deployment models may include:

* remote evidence forwarding,
* signed event chains,
* hash-linked evidence,
* external timestamping,
* write-restricted collectors,
* immutable object storage,
* multi-node evidence replication.

## 14. Future Evidence Core

The current repository implements forensic processing components. The broader Evidence Core architecture may later add:

```text
Evidence Sources
        |
        v
Collection
        |
        v
Parsing
        |
        v
Normalization
        |
        v
Local Evidence Store
        |
        +----------> Correlation and Reconstruction
        |
        +----------> Detection
                            |
                            v
                         Alerting
```

Potential Evidence Core responsibilities include:

* observing new source events,
* preserving source identity,
* maintaining collection cursors,
* avoiding unnecessary duplication,
* recovering after restart,
* append-oriented evidence storage,
* controlled rotation,
* collector health reporting.

Operational state must remain distinct from evidence.

Examples of operational state include:

* source cursor positions,
* last processed journal cursor,
* file observation metadata,
* deduplication state,
* collector health information.

Loss of operational state must not invalidate evidence already collected.

## 15. Detection and Alerting Direction

Detection and alerting are consumers of evidence, not prerequisites for evidence collection.

Future detection capabilities may include:

* repeated authentication failure detection,
* unusual authentication patterns,
* changes to SSH trust material,
* privileged execution findings,
* critical path modification findings,
* cross-event correlation,
* severity assignment.

Future alert providers may include:

* email,
* webhook,
* messaging platforms,
* SIEM integrations,
* external incident management systems.

Detection or alert delivery failure must not stop the Evidence Core.

## 16. Failure Isolation

The architecture should isolate failures between components.

The following future failures must not stop evidence collection:

* malformed detection rules,
* alert provider failure,
* network outage,
* remote collector outage,
* dashboard outage,
* reporting failure.

The core objective remains durable evidence collection and reliable reconstruction.

## Architectural Direction

SSH Blackbox should evolve from a reliable local forensic evidence processor into a broader distributed forensic telemetry system without sacrificing conservative reasoning or operational simplicity.

Evidence comes first.

Correlation explains relationships.

Reconstruction organizes supported facts.

Unlinked evidence remains evidence.

Detection interprets evidence.

Alerting communicates findings.
