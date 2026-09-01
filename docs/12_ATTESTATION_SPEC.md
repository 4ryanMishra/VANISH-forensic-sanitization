# VANISH — Attestation & Certificate Spec

This addendum defines the signing/attestation layer referenced in the VANISH
pitch (Ed25519 + hash-chained signed certificates) that `01_MASTER_ENGINEERING_SPEC.md`
does not yet specify. Read this alongside `06_API_CONTRACTS.md`'s `AuditEvent`.

## 1. Purpose

The audit chain (`AuditEvent.previous_event_hash`) proves internal
consistency — that no event was inserted, deleted, or reordered after the
fact. It does NOT by itself prove the chain came from a real VANISH run on
real hardware, or that it hasn't been regenerated wholesale by someone with
access to the machine. Signing closes that gap: it binds the chain to a key,
so a third party can verify authorship without trusting the machine that
produced it.

Two independent guarantees, do not conflate them:
- **Chain integrity** (hash-linking): "this sequence of events was not
  edited after being appended."
- **Authorship** (signing): "this sequence of events was produced by a key
  we can verify, at the time claimed."

## 2. Key model

```text
SigningIdentity {
  key_id
  public_key        // Ed25519, 32 bytes
  created_at
  scope             // "session" | "device" | "operator"
  storage           // where the private key lives (see below)
}
```

For the hackathon build, in order of increasing trust and increasing
implementation cost:

1. **Session key** — generated fresh per VANISH run, held in memory only,
   discarded on exit. Cheapest to implement. Proves "these events came from
   one continuous run," not "came from a specific person/machine."
2. **Machine key** — generated once per install, persisted to disk
   (unencrypted is acceptable for a demo; note this as a limitation).
   Proves continuity across runs on the same machine.
3. **TPM-anchored key** — private key sealed in the TPM, never exportable,
   signing operation happens inside the TPM. This is the version referenced
   in the pitch deck as the "closes the last trust gap" feature.

**Recommendation given your hardware (no dedicated SSD, laptops not to be
risked):** implement (1) and (2) for the working build. Treat (3) as a
documented stretch goal / architecture diagram item, not something agents
attempt against your primary laptops. TPM signing requires a TPM you
control and are willing to write to — do not point this at your personal
laptop's TPM for a hackathon prototype. If you want to demo (3) credibly,
do it against a disposable/VM environment and say so explicitly in the demo
narrative — this is consistent with `05_AGENT_RULES.md`'s "clearly label
simulations" rule.

## 3. Certificate structure

Issued once per completed sanitization or recovery-validation job.

```text
SanitizationCertificate {
  cert_id
  cert_version
  issued_at
  device_identity          // stable_id, model, serial, capacity
  operation_summary        // policy, method, parameters
  verification_result      // the L1-L4 VerificationResult, unmodified
  audit_chain_root_hash    // hash of the last AuditEvent in the chain
  audit_event_count
  signing_identity {
    key_id
    public_key
  }
  signature                // Ed25519 sig over the canonical serialization
                            // of every field above except `signature` itself
}
```

Hashing: BLAKE3 or SHA-256 (pick one, do not mix per `02_TECH_STACK.md`'s
hashing library — consistency matters more than which algorithm).

Signing: Ed25519 over a canonical (deterministic field order, no
whitespace ambiguity) serialization of the certificate body.

## 4. Verification procedure (what a judge/auditor does)

```text
1. Recompute audit_chain_root_hash from the raw AuditEvent log
   → must match cert.audit_chain_root_hash
2. Verify cert.signature against cert.public_key
   → must be valid
3. (Optional, higher trust) Verify cert.public_key against a
   previously-published/pinned key for this device or session
   → confirms authorship, not just "some key signed this"
```

Step 3 is why key distribution matters: a self-signed cert with no
independent record of the public key only proves internal consistency, not
who produced it. For the demo, publishing the session/machine public key
at the start of the run (e.g., displayed on screen, written to a
judge-visible location before the destructive operation begins) is
sufficient to make step 3 meaningful without needing real PKI.

## 5. What NOT to claim

Consistent with `01_MASTER_ENGINEERING_SPEC.md` §11 and `09_DEMO_WORKFLOW.md`:
- Do not claim the certificate proves data is unrecoverable by any party
  under any circumstances. It proves: this operation ran, reported this
  result, and this record has not been altered since — nothing about
  physical media forensics beyond what `VerificationResult` already scopes.
- Do not claim TPM-anchoring is implemented if it is only diagrammed. Keep
  the pitch deck's TPM mention and the actual build in sync — if it's not
  built, say "architected for, not yet implemented" on the slide.

## 6. Ownership

Given the two-person split in `04_TEAM_SPLIT.md`, this module sits under
`src-tauri/src/audit/` and is Aryan's ownership (device/sanitization side),
since it consumes `AuditEvent` and `VerificationResult` directly. Subodeep's
forensic-side `RecoveredArtifact` should also get a hash/provenance field
covered by the same signing identity when recovery jobs are certified —
keep one signing module shared between both flows rather than duplicating it.
