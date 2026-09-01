# VANISH — API Contracts

## Device

```text
Device {
  stable_id
  path
  model
  serial
  capacity
  logical_block_size
  physical_block_size
  interface
  media_type
  mounted
  boot_device
  read_only
  capabilities
}
```

## SanitizationPlan

```text
SanitizationPlan {
  target_id
  method
  rationale
  prerequisites
  warnings
  verification_plan
  simulation
}
```

## VerificationResult

```text
VerificationResult {
  logical_status
  host_visible_status
  device_reported_status
  forensic_validation_status
  scope
  warnings
}
```

Do NOT create a generic `guaranteed_deleted: bool`.

## RecoveredArtifact

```text
RecoveredArtifact {
  source_id
  source_offsets
  format
  path
  size
  sha256
  validation_status
  confidence
  provenance
}
```

## AuditEvent

```text
AuditEvent {
  event_id
  timestamp
  actor
  operation
  target_id
  parameters
  result
  verification
  error
  previous_event_hash
}
```

## Job states

```text
CREATED
VALIDATING
READY
ARMED
RUNNING
VERIFYING
COMPLETED
FAILED
CANCELLED
```
