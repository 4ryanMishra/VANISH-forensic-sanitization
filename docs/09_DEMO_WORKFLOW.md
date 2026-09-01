# VANISH — End-to-End Demo

## Narrative

```text
Normal deletion
 ↓
Forensic recovery
 ↓
Hash + validation
 ↓
Device-aware sanitization
 ↓
Verification
 ↓
Forensic validation attempt
 ↓
Audit report
```

## Step 1

Create disposable files:

```text
CONFIDENTIAL/
├── project.pdf
├── image.jpg
└── secret.txt
```

Hash them.

## Step 2

Delete `project.pdf` normally.

Explain that filesystem deletion does not automatically mean underlying bytes are gone.

## Step 3

Run read-only recovery:

```text
RAW SCAN
 ↓
signature
 ↓
candidate
 ↓
reconstruction
 ↓
format validation
 ↓
SHA-256
```

Open recovered copy.

## Step 4

Select disposable device and show identity/capabilities.

## Step 5

Select policy.

## Step 6

Explicit safety confirmation.

## Step 7

Execute supported procedure.

## Step 8

Show verification levels.

## Step 9

Run forensic validation again.

Before:

```text
FOUND → RECOVERED → VALIDATED
```

After:

```text
TARGET NOT RECOVERED BY DEFINED PROCEDURE
```

## Step 10

Generate audit/report.

Never claim universal impossibility.
