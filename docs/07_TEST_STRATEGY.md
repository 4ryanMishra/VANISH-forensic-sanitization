# VANISH — Test Strategy

Most development must work without physical hardware.

## Unit tests

Test signatures, parsers, hashing, device models, policy selection, safety checks, audit hashing and reconstruction scoring.

## Virtual disk tests

Create deterministic images containing:
- existing files;
- deleted files;
- contiguous files;
- fragmented files;
- corrupted files;
- false signatures.

Store ground-truth hashes.

## Integration

Test:

```text
Device → Capability → Policy
Image → Recovery → Validation
Operation → Verification → Audit
```

## Safety

Mandatory:
- system disk detection;
- boot disk rejection;
- ambiguous identity rejection;
- unsupported capability rejection;
- device disappearance;
- identity change;
- simulation cannot write;
- forensic mode cannot write;
- destructive mode requires explicit arm.

## Physical

Only use disposable storage. Record device, firmware, interface, capacity, filesystem, exact procedure, result, verification and limitations.

## Recovery metrics

Detection rate, true recovery rate, false positives, fragmented recovery rate, throughput, CPU, memory and latency.

## Sanitization metrics

Command acceptance, execution time, device completion result, verification outcome and failure modes.
