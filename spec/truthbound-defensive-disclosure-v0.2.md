# Delayed public evidence of security safeguards using salted fingerprints, collector identity, a hash-chained log and Bitcoin timestamps (Truthbound)

Defensive publication. Version 0.2, final draft for approval. Not yet published.
Inventor: Aaron Melear. Publisher: UnderHype LLC (Idaho, USA). Contact: aaron@underhype.ai.
Publication date: the date recorded by the venue. The SHA-256 fingerprint of this file is timestamped with OpenTimestamps; the proof is published with the specification repository.
License: this document is licensed under Creative Commons Attribution 4.0 (CC BY 4.0). Patent promise: see section 13.

Keywords: security evidence, control monitoring, trust center, transparency log, hash chain, salted commitment, timestamping, OpenTimestamps, Bitcoin, RFC 3161, SCITT, CIS Controls, Implementation Group 1, safeguard mapping, publication delay, remediation window, collector provenance, reproducible build, buyer verification, vendor risk.

## 1. Purpose of this disclosure

This document describes a method and system so that it is available to the public as prior art. It is meant to be detailed enough for a person skilled in software and security engineering to build the system from this document alone. Section 9 describes alternatives. Each one is part of this disclosure, alone and in any combination with the others.

## 2. Problem

Small and mid-sized organizations are asked by customers, partners and insurers to show that their security safeguards are in place. Today they usually answer with questionnaires, screenshots or a trust page that the organization writes and can change at any time. A reader can't tell:
- whether a stated check actually ran on a given day,
- what software produced the result,
- whether a failure was quietly removed later, or
- whether the evidence shown to one buyer matches what was recorded at the time.

Formal audits answer some of this, but they are costly, happen once a year and look at a sample.

## 3. Related work this builds on

- Hash-based timestamping of documents: Haber and Stornetta (1991); RFC 3161 time stamp authorities; Guardtime KSI.
- Public blockchain timestamping of digests: OpenTimestamps (aggregates digests into a Merkle tree and commits the root in a Bitcoin transaction); Chainpoint.
- Append-only transparency logs: Certificate Transparency (RFC 6962, RFC 9162); Sigstore Rekor; IETF SCITT architecture (RFC 9943) and related drafts, including drafts on Bitcoin-anchored time proofs and digest-only evidence logs.
- Software supply chain provenance: in-toto, SLSA provenance, reproducible builds.
- Open source evidence collectors that map results to security controls and produce hashed evidence packs.

The system below combines and extends these for continuous, delayed, publicly checkable evidence of an organization's security safeguards.

## 4. Overview

On a schedule (for example daily), a collector program:
1. reads configuration and status data from the organization's systems,
2. reduces that data to only the fields needed for the check,
3. removes personal and sensitive details,
4. records which collector software produced the result,
5. adds a secret random value (a nonce),
6. serializes the result to canonical bytes and computes a cryptographic fingerprint,
7. stores the full evidence privately,
8. timestamps the fingerprint against a public, hard-to-change record such as the Bitcoin blockchain, and
9. appends an entry to a public, hash-chained log.

A public page shows, for each safeguard, the status and the fingerprint and timestamp proof for each check. It shows each result only after a fixed delay (for example 7 days). The delay gives the organization a short window to fix a failure. The failure itself is fingerprinted and timestamped on the day it is found, so the delay can't hide it, and the page keeps every failure in its history, including ones fixed during the window.

A buyer who receives an evidence file privately (for example under an NDA) can hash that file on their own device and see whether it matches a public fingerprint and timestamp.

## 5. Components

### 5.1 Controls and framework mapping
- The system defines its own controls with stable identifiers and short plain names, for example "unused-accounts" (unused accounts are turned off) or "two-step-sign-in" (two-step sign-in is required).
- Each control lists the sources it reads and its schedule (daily, weekly, monthly or on event).
- A separate mapping file links each control to one or more external framework references, for example CIS Critical Security Controls v8.1 Implementation Group 1 safeguard numbers. The mapping holds only reference numbers and the system's own short names, with credit and a non-endorsement line. The framework's text is not copied.
- Keeping controls and mappings separate lets one control map to several frameworks, and lets a framework version change without rewriting history.

### 5.2 Source adapters
- There is one adapter per source system: an identity provider and device directory, a code host, a cloud or hosting provider, a multi-factor authentication service, a chat workspace, a backup store, and others.
- Each adapter uses read-only credentials, makes a fixed set of named calls, and returns raw responses in memory only.
- An adapter can be marked pending. The control still runs, and the evidence records which sources were pending.

### 5.3 Check logic
- For each control, the check logic turns the raw data into a small summary of counts and true or false values, for example the number of active accounts with no sign-in in 45 days, how many merged code changes had an approving review, or the days since the last good backup.
- It also sets an open_item flag when the safeguard isn't met.

### 5.4 Projection (allowlist)
- For every named source call there is a projection that keeps only listed scalar fields: flags, setting values, counts, dates, request or run numbers, and event and role names.
- A call with no projection fails closed: its raw response is never stored or hashed.

### 5.5 Redaction (denylist)
After projection, a second pass removes:
- personal names, emails, account names, device names and identifiers,
- network addresses,
- content,
- secrets and tokens,
- long numeric identifiers,
- keys ending in "id" unless they are on a keep list, and
- a private term list (for example client or project names).

Before hashing, a guard scans the canonical bytes for any configured credential value or private term. If it finds one, it aborts that control for the day.

### 5.6 Evidence document
The evidence document is a JSON object with, for example:
- format: an evidence format identifier and version
- control: the control identifier
- run_date: the scheduled day
- collected_at: the actual collection time (ISO 8601, UTC)
- collector: the collector identity (see 5.7)
- pending_sources: a list
- manual_items: manual items attached to the control
- summary: the counts, true or false values and open_item
- sources: the projected and redacted data per source and call
- nonce: 32 random bytes, hex encoded

### 5.7 Collector identity
The evidence and the public log entry both name the software that produced the result. This lets a reader link a result to a specific, inspectable version of open source code. Embodiments include, alone or combined:
- a name and version string,
- the source control commit hash of the collector code,
- a cryptographic digest of the collector's source files or built artifact,
- a digest of a reproducible build, so anyone can rebuild the code and compare,
- a signed provenance statement from the build or run environment (for example SLSA or in-toto), and
- a digest of the collector configuration, with secrets excluded.

In each case, the collector identity is part of the fingerprinted bytes and the public entry. That means one public timestamp binds both what was found and which code found it.

### 5.8 Canonical bytes and fingerprint
- The document is serialized as canonical JSON: object keys sorted, no whitespace, UTF-8, with non-finite numbers and undefined values rejected.
- The fingerprint is a cryptographic hash of exactly those bytes, for example SHA-256.
- The hash algorithm is chosen through a registry, so a stronger algorithm can be added later without changing callers. The algorithm name is recorded with each fingerprint.

### 5.9 Salted commitment
- The nonce is included in the hashed bytes and kept only in the private evidence document.
- Without it, someone could guess likely evidence contents (for example "0 unused accounts") and confirm a guess against the public fingerprint. With it, the public fingerprint reveals nothing about the evidence.
- A party who receives the full evidence file, including the nonce, can still recompute the fingerprint exactly.

### 5.10 Private evidence store
- The canonical bytes are stored privately under their fingerprint, for example in an object store bucket with a retention policy.
- They are released only to chosen parties, for example a buyer under an NDA, an auditor or an insurer.

### 5.11 Timestamp anchor
- The fingerprint is submitted to at least two OpenTimestamps calendar servers. Each returns a pending proof, and the system needs at least two responses.
- Later, an upgrade step replaces each pending proof with a complete proof that runs to a Bitcoin block header. Upgrades are accepted only from an allowlist of calendar servers.
- Proofs are stored as .ots files under the fingerprint.
- Anchors are pluggable, through a common interface: name, stamp(digest), upgrade(proof) and status(proof).
- A second anchor can periodically commit the head of the log (see 5.12), for example monthly, through a Bitcoin OP_RETURN output or another public ledger.

### 5.12 Hash-chained public log
- The log is append-only JSON Lines.
- Each entry has: v (format version), seq (0, 1, 2 and so on), prev (the previous entry's hash, or null), statement, subject, content_hash, proof, and entry_hash.
- The statement holds: type, control, schedule, run_date, collected_at, open_item, the count of pending sources, the count of manual items, and the collector identity.
- The subject holds the control and a reference to the private evidence by fingerprint. The content_hash holds the algorithm and the value. The proof holds the anchor type and a reference to the proof file.
- entry_hash is the hash of the canonical bytes of the entry without entry_hash.
- Before each append, the whole chain is checked for sequence gaps, wrong previous hashes and wrong entry hashes. The system refuses to append to a broken chain.
- The entry shape lets each entry later be wrapped as a SCITT signed statement with a receipt from a transparency service, without rewriting history.

### 5.13 Fail-closed runs and missed checks
- If any step fails for a control (a source error, a missing projection, a leak guard, the hash, the store or the anchor), nothing is written for that control that day.
- Errors record only the source, the call name and the HTTP status, never response bodies.
- The page later shows that day as missed for that control.

### 5.14 Delayed public page
The page is built from the public log by pure functions. For example:
- Only entries collected more than D days before build time are shown (D = 7 in one embodiment).
- For each control, the page shows a full history from the first scheduled day to the last day fully past the delay, with each day labeled:
  - ran,
  - open (the safeguard isn't met),
  - new open (it changed from met to not met),
  - closed (it changed from not met to met),
  - missed (no entry for a scheduled day; the last shown day is never marked missed while it may still be running), or
  - late (collected after its scheduled day).
- Each row shows the real collection time, the fingerprint, the algorithm, the proof link and the log sequence number.
- Failures fixed within the delay stay visible in the history, with the day each started and the day it was fixed.
- The page states the delay plainly near the status: a failure gets up to D days to be fixed before it shows, it is recorded and timestamped the day it is found, and anything still open after D days shows as failing.
- A wording checker runs at build time and refuses to publish a page with banned claims (for example "certified", "compliant", "guaranteed"), people's names, email or network addresses, internal system names or internal IDs. It also requires the framework credit and non-endorsement lines.

### 5.15 Buyer check
- The page includes a client-side tool. A buyer selects or drops an evidence file they received privately.
- The browser hashes the file locally (for example with the Web Crypto API), with no network request, and compares the result with the published fingerprints.
- If it matches, it shows the safeguard, the check date and a link to the timestamp proof. The buyer can check that proof against Bitcoin with any OpenTimestamps verifier.
- If it doesn't match, it says so.

## 6. Method, step by step

For each control C on its scheduled day d:
1. For each source s of C: if s is pending, add it to pending; otherwise raw[s] = adapter_s.collect(C).
2. summary = check_C(raw, now, config).
3. For each source call k: projected[s][k] = projection_s,k(raw[s][k]). Fail if the projection is missing.
4. doc = { format, control: C, run_date: d, collected_at: now, collector: identity, pending_sources, manual_items, summary, sources: projected }.
5. doc' = redact(doc, keep list, private terms).
6. n = 32 random bytes.
7. bytes = canonical_json(doc' with nonce = hex(n)).
8. If bytes contains any credential value or private term, abort C for day d.
9. f = H(bytes).
10. private_store.put(f, bytes).
11. proof = anchor.stamp(f); proof_store.put(f, proof).
12. log.append(statement, subject, content_hash = {alg, f}, proof ref).
13. If any step fails, write nothing for C on day d.

Later:
- upgrade(proof) until each proof is complete.
- At build time t, render the page from entries with collected_at < t - D.

To verify, a buyer with an evidence file E:
1. Compute H(E) locally and find the matching fingerprint on the page.
2. Verify the .ots proof against the Bitcoin block header.
3. Optionally verify the log chain from seq 0 to the head, and the head anchor.
4. Optionally rebuild the collector from the named commit or artifact digest and inspect or run it.

## 7. Example public log entry (fictional values)

```json
{"v":1,"seq":41,"prev":"sha-256:9f2c...e1","statement":{"type":"truthbound.posture.check/v1","control":"unused-accounts","schedule":"daily","run_date":"2026-11-10","collected_at":"2026-11-10T13:02:11.000Z","open_item":false,"pending_sources":1,"manual_items":0,"collector":"example-collector/0.1.0"},"subject":{"control":"unused-accounts","evidence":"evidence/3b7a...c4.json"},"content_hash":{"alg":"sha-256","value":"3b7a...c4"},"proof":{"type":"opentimestamps","ref":"proofs/3b7a...c4.ots"},"entry_hash":"sha-256:51d0...8a"}
```

## 8. Data flow

```
sources -> check (in memory) -> projection (allowlist) -> redaction (denylist, private terms)
  -> add nonce -> canonical bytes -> leak guard -> hash
  -> private evidence store
  -> timestamp anchor (OpenTimestamps / Bitcoin) -> proof store
  -> hash-chained public log -> (delay D) -> public page and buyer check
```

## 9. Alternatives and variations

Each alternative below is disclosed alone and in combination with the others.

### Schedule and timing
- Run on any schedule (hourly, daily, weekly, monthly), on an event (a configuration change or an alert) or on demand.
- Use any delay D of zero or more days, or set D per control or by severity.
- Pick a random delay within a range so readers can't infer exact fix times.
- Have no delay, with an immediate public status.
- Show a failure right away while hiding its details for D days.
- Expire the window early when a failure is fixed.

### What is fingerprinted
- Fingerprint one document per control per run, one per run for all controls, one per source call, or a Merkle tree over per-control documents with only the root anchored.
- Use any hash function: SHA-256, SHA-3, BLAKE2 or BLAKE3, or several at once.
- Use a salted commitment, a keyed MAC with a later key reveal, or a Pedersen or other commitment scheme.
- Use zero-knowledge proofs that a hidden evidence value meets a condition (for example a count below a threshold) without revealing it.
- Use selective disclosure, where each field is separately salted and hashed and some fields are revealed to some readers.

### Collector identity
- Use any of the forms in 5.7.
- Run the collector in a trusted execution environment or a confidential VM, with a remote attestation report included in the evidence.
- Run the collector on a third-party CI service with signed provenance.
- Have several independent collectors check the same safeguard, with results compared.

### Timestamp and anchoring
- Anchor through OpenTimestamps on Bitcoin.
- Commit directly with a Bitcoin OP_RETURN, a Taproot commitment or another output type.
- Use another public blockchain or distributed ledger.
- Use an RFC 3161 time stamp authority, or several.
- Use a SCITT transparency service receipt, a Certificate Transparency style log, or Sigstore Rekor.
- Publish in a newspaper or another widely witnessed medium.
- Use any combination: per-entry anchoring, periodic anchoring of the log head, or both.

### Log
- Use JSON Lines, CBOR or COSE, a Merkle tree log with inclusion and consistency proofs, a database with a hash chain, or a git repository whose commits form the chain.
- Sign entries with an organization key, a hardware key or keyless signing, with signatures included in the entry.
- Wrap entries as SCITT signed statements and register them with one or more transparency services.

### Sources and controls
- Use any source: identity providers, device management, endpoint detection, code hosts, CI/CD, cloud and hosting providers, DNS, email security, backup systems, password managers, ticketing and HR systems.
- Include manual or attested items with a person's signed statement, fingerprinted the same way.
- Map to any framework, alone or several at once: CIS Controls (any Implementation Group), NIST CSF, NIST 800-53 or 800-171, ISO/IEC 27001, SOC 2 criteria, HIPAA safeguards, PCI DSS, cyber insurance questionnaires, or customer-specific control lists.

### Disclosure and verification
- Release evidence to chosen parties under an NDA, through a portal, by email, or through a time-limited link.
- Have an auditor, insurer, managed service provider or buyer re-run the collector against the same sources and compare fingerprints.
- Perform the buyer check in a browser, a command line tool, a mobile app or a server API.
- Feed results into a vendor-risk platform, a procurement system, an insurance application or a partner portal.

### Who runs it
- The organization itself.
- A managed service provider running one collector per client and publishing one page per client, or an aggregate page.
- A platform hosting many organizations' logs and pages.
- A standards body or nonprofit maintaining the collector and the mapping.

### Page
- A static site, a dynamic site, an embeddable badge or widget, a machine-readable feed (JSON, RSS or a SCITT feed), or an API.
- History shown as a table, a calendar, a timeline or a chart.
- Summary scores or counts per framework, without claims of certification.

## 10. Advantages

- Readers can check that a stated safeguard check ran on a stated day with stated code, without trusting the organization's page.
- Failures can't be quietly erased, because each one is timestamped the day it is found and stays in the history.
- The delay gives a fair, short remediation window that is disclosed publicly.
- Public fingerprints reveal nothing about the evidence, because of the nonce.
- Personal and sensitive data stay private, because of the allowlist, the denylist and the leak guard.
- It is low cost: open source code, read-only API access and public timestamp calendars.

## 11. Limits

- This system shows what the collector observed through the listed sources. It isn't an audit, certification or assurance opinion.
- A collector can only check what its sources expose.

## 12. References

- S. Haber and W. S. Stornetta, "How to Time-Stamp a Digital Document," Journal of Cryptology 3 (1991).
- RFC 3161, Time-Stamp Protocol: https://www.rfc-editor.org/rfc/rfc3161
- OpenTimestamps: https://opentimestamps.org/
- RFC 6962 and RFC 9162, Certificate Transparency: https://www.rfc-editor.org/rfc/rfc9162
- RFC 9943, SCITT architecture, and related SCITT drafts: https://datatracker.ietf.org/wg/scitt/documents/
- Sigstore Rekor: https://docs.sigstore.dev/logging/overview/
- in-toto: https://in-toto.io/ and SLSA: https://slsa.dev/
- CIS Critical Security Controls: https://www.cisecurity.org/controls

## 13. License and patent promise

- This document: CC BY 4.0.
- Reference code (when published): Apache License 2.0.
- Patent promise: UnderHype LLC makes this specification available under the Open Web Foundation Final Specification Agreement (OWFa 1.0).
- UnderHype LLC intends this document to serve as prior art, and has not filed and does not intend to file patent applications on the method described here.

CIS Controls is a trademark of the Center for Internet Security, Inc. CIS hasn't reviewed or endorsed this document. CIS does not sponsor or endorse this project.
