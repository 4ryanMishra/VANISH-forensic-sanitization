# VANISH — GitHub, Root Folder & Two-Agent Coordination Guide

## Purpose

This document is the operating agreement for both developers and both Antigravity agents.

The goal is to prevent the project from becoming two agents independently generating code that later becomes impossible to integrate.

**Rule #1: GitHub is the source of truth.**

**Rule #2: `/docs` defines architecture; code implements it.**

**Rule #3: Neither agent silently changes another subsystem's contract.**

---

# 1. Repository model

Use ONE GitHub repository:

```text
VANISH/
```

Both developers clone the same repository.

Do NOT create separate repositories for the two halves.

Recommended:

```text
GitHub
└── VANISH
    ├── main
    ├── develop
    ├── feature/device-sanitization
    ├── feature/forensics-recovery
    ├── feature/ui
    └── feature/integration
```

For a two-person project, `main + feature branches` is enough. `develop` is optional.

---

# 2. Final root folder

Both agents must work from the same root:

```text
VANISH/
│
├── README.md
├── LICENSE
├── .gitignore
├── Cargo.toml
├── package.json
│
├── docs/
│   ├── 00_MASTER_README.md
│   ├── 01_MASTER_ENGINEERING_SPEC.md
│   ├── 02_TECH_STACK.md
│   ├── 03_REPOSITORY_STRUCTURE.md
│   ├── 04_TEAM_SPLIT.md
│   ├── 05_AGENT_RULES.md
│   ├── 06_API_CONTRACTS.md
│   ├── 07_TEST_STRATEGY.md
│   ├── 08_PHYSICAL_LAB.md
│   ├── 09_DEMO_WORKFLOW.md
│   ├── 10_IMPLEMENTATION_ROADMAP.md
│   ├── 11_AGENT_BOOTSTRAP_PROMPT.md
│   └── 12_GITHUB_COORDINATION.md
│
├── src/
│   ├── components/
│   ├── pages/
│   ├── services/
│   ├── hooks/
│   ├── types/
│   └── app/
│
├── src-tauri/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── lib.rs
│       │
│       ├── common/
│       │
│       ├── device/
│       ├── platform/
│       ├── policy/
│       ├── sanitization/
│       ├── deletion/
│       ├── verification/
│       ├── audit/
│       ├── reporting/
│       │
│       └── forensic/
│           ├── imaging/
│           ├── filesystem/
│           ├── carving/
│           ├── reconstruction/
│           └── validation/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── recovery/
│   ├── sanitization/
│   └── safety/
│
├── test-data/
│   ├── virtual-disks/
│   ├── sample-files/
│   └── expected-results/
│
├── lab/
│   ├── scripts/
│   └── configs/
│
└── tools/
```

Do not randomly create folders such as:

```text
final/
new/
new2/
agent-code/
working/
backup/
test-final/
```

If a new architectural folder is needed, document it first.

---

# 3. Ownership map

## Agent A — Device & Sanitization

Owns:

```text
src-tauri/src/device/
src-tauri/src/platform/
src-tauri/src/policy/
src-tauri/src/sanitization/
src-tauri/src/deletion/
src-tauri/src/verification/
src-tauri/src/audit/
```

Primary responsibilities:

- device discovery;
- device identity;
- media classification;
- capability detection;
- boot/system-disk detection;
- sanitization policy;
- safety gates;
- sanitization execution adapters;
- targeted deletion;
- verification;
- audit events.

---

## Agent B — Forensics & Recovery

Owns:

```text
src-tauri/src/forensic/
```

Primary responsibilities:

- read-only acquisition;
- virtual disk handling;
- filesystem analysis;
- raw scanning;
- signature detection;
- contiguous carving;
- fragmented-file reconstruction;
- format validation;
- recovered artifact metadata;
- recovery confidence;
- recovery metrics.

---

## Shared

Both agents may modify:

```text
src-tauri/src/common/
src/
tests/integration/
docs/
```

But shared files require coordination.

---

# 4. The most important boundary

The two agents must communicate through interfaces.

Conceptually:

```text
                 COMMON CONTRACTS
                       │
          ┌────────────┴────────────┐
          ↓                         ↓
   DEVICE/SANITIZATION          FORENSICS
       Agent A                    Agent B
          │                         │
          └────────────┬────────────┘
                       ↓
                  ORCHESTRATOR
                       ↓
                       UI
```

Agent B should NOT call Agent A's private internal functions directly.

Agent A should NOT depend on Agent B's internal implementation.

They communicate through stable models and service interfaces.

---

# 5. Shared contracts come first

Before serious parallel development, agree on:

```text
Device
DeviceCapability
SanitizationPlan
VerificationResult
RecoveredArtifact
AuditEvent
Job
JobStatus
```

These live under:

```text
src-tauri/src/common/
```

Example:

```text
common/
├── device.rs
├── job.rs
├── recovery.rs
├── sanitization.rs
├── verification.rs
├── audit.rs
└── mod.rs
```

The exact Rust design can evolve, but the semantic meaning must remain stable.

---

# 6. Git branch rules

Each agent works on its own feature branch.

## Agent A

```bash
git checkout -b feature/device-sanitization
```

## Agent B

```bash
git checkout -b feature/forensics-recovery
```

Do NOT both develop directly on `main`.

---

# 7. Commit rules

Commits should represent ONE logical change.

Good:

```text
feat(device): add Linux block-device discovery
feat(forensics): add JPEG signature scanner
feat(policy): add capability-based plan selection
test(carving): add contiguous PDF fixture
fix(audit): correct event hash chaining
docs: define verification levels
```

Bad:

```text
update
changes
final
done
stuff
working
fixed everything
```

The commit message should tell the team what changed without opening the diff.

---

# 8. Pull request rules

Every feature goes:

```text
feature branch
      ↓
tests
      ↓
push
      ↓
Pull Request
      ↓
other developer reviews
      ↓
merge
```

Before opening a PR:

```bash
git status
git diff
cargo test
```

Also run the frontend tests/build where applicable.

A PR description must contain:

```text
## What changed

## Why

## Files/modules changed

## Tests added

## Tests run

## API/contract changes

## Hardware requirements

## Safety implications

## Integration notes
```

---

# 9. Agent coordination protocol

Every morning/session, both developers should update a tiny coordination file:

```text
docs/WORK_STATUS.md
```

Format:

```markdown
# Current Work

## Agent A
Status:
Working on:
Branch:
Blocked by:
Next:

## Agent B
Status:
Working on:
Branch:
Blocked by:
Next:

## Shared
Current integration target:
Contract changes:
Known conflicts:
```

This prevents both agents from unknowingly solving the same problem.

---

# 10. Task IDs

Use simple task IDs.

```text
DEV-A-001
DEV-A-002
DEV-A-003

DEV-B-001
DEV-B-002
DEV-B-003

INT-001
INT-002
INT-003
```

Example:

```text
DEV-A-001 → Linux device discovery
DEV-A-002 → boot-device safety check
DEV-A-003 → capability model

DEV-B-001 → virtual image reader
DEV-B-002 → signature scanner
DEV-B-003 → contiguous carving

INT-001 → connect recovery engine to orchestrator
INT-002 → connect device engine to UI
```

Put these IDs in GitHub Issues.

---

# 11. Recommended GitHub project board

Columns:

```text
BACKLOG
   ↓
READY
   ↓
IN PROGRESS
   ↓
REVIEW
   ↓
INTEGRATION
   ↓
TESTING
   ↓
DONE
```

Labels:

```text
agent-a
agent-b
shared
frontend
backend
forensics
sanitization
safety
hardware
bug
documentation
high-priority
```

---

# 12. Dependency-aware development

Do NOT start with physical destructive operations.

Correct sequence:

```text
Architecture
     ↓
Common contracts
     ↓
Virtual laboratory
     ↓
Device discovery
     ↓
Forensic recovery
     ↓
Policy simulation
     ↓
Verification
     ↓
Audit
     ↓
UI
     ↓
Integration
     ↓
Disposable physical media
     ↓
Device-specific operations
```

This is important because the agents can develop ~80–90% of the architecture without risking hardware.

---

# 13. Parallel workflow

After contracts are frozen:

```text
                 COMMON MODELS
                      │
          ┌───────────┴───────────┐
          ↓                       ↓
      AGENT A                  AGENT B
   Device/Sanitize          Forensic/Recovery
          │                       │
          ↓                       ↓
      Unit tests              Unit tests
          │                       │
          └───────────┬───────────┘
                      ↓
                INTEGRATION
                      ↓
                     UI
```

Do not wait for one entire subsystem to be finished before beginning the other.

---

# 14. Integration checkpoints

Use explicit checkpoints.

## Checkpoint 1 — Contracts

Both agents compile against common models.

## Checkpoint 2 — Forensic MVP

Agent B can:

```text
virtual image
→ scan
→ identify
→ recover
→ validate
→ hash
```

## Checkpoint 3 — Device MVP

Agent A can:

```text
device
→ identify
→ classify
→ detect capabilities
→ detect boot/system status
```

## Checkpoint 4 — Simulation

Agent A can:

```text
device
→ capability
→ policy
→ sanitization plan
→ simulated execution
→ simulated verification
```

## Checkpoint 5 — Full software integration

```text
UI
 ↓
Orchestrator
 ↓
Device/Forensic engine
 ↓
Verification
 ↓
Audit
 ↓
Report
```

## Checkpoint 6 — Physical lab

Only now use disposable hardware.

---

# 15. How agents should handle conflicts

If both agents modify the same file:

1. Stop.
2. Do not blindly resolve the conflict with generated code.
3. Compare intent.
4. Decide which architecture is correct.
5. Merge manually.
6. Add a test.
7. Document the decision if architectural.

Especially protect:

```text
common/
Cargo.toml
Tauri commands
shared TypeScript types
orchestrator
```

---

# 16. Agent-to-agent handoff format

When Agent A needs something from Agent B:

```markdown
## Handoff: A → B

Task:
Why needed:

Expected interface:

Input:

Output:

Error cases:

Tests required:

Deadline/priority:
```

Example:

```markdown
## Handoff: A → B

Task:
Expose Device identity to the recovery workflow.

Expected interface:
Device { stable_id, path, model, serial, capacity }

Input:
Device ID

Output:
Device metadata

Error cases:
Device disappeared / permission denied

Tests:
Mock device discovery.
```

---

# 17. Definition of Done

A task is NOT done merely because the agent generated code.

A task is done when:

```text
Code
 +
Tests
 +
Documentation
 +
Integration notes
 +
Clean build
```

Minimum checklist:

- [ ] implementation complete;
- [ ] unit tests;
- [ ] error handling;
- [ ] no unsafe assumptions;
- [ ] docs updated;
- [ ] no unrelated files changed;
- [ ] branch pushed;
- [ ] PR opened;
- [ ] second developer reviewed.

---

# 18. Physical hardware rule

The physical SanDisk USB is a shared laboratory resource.

Neither agent should independently perform destructive experiments.

Before any physical destructive test:

```text
1. Identify device
2. Confirm serial/path
3. Confirm capacity
4. Confirm it is NOT the system disk
5. Confirm disposable data
6. Confirm operation
7. Record experiment ID
8. Run
9. Verify
10. Record result
```

If identity is ambiguous:

```text
STOP
```

The tool should fail closed.

---

# 19. Simulation-first rule

Every hardware-facing component should have a simulator/mock where practical.

Example:

```text
RealDeviceAdapter
MockDeviceAdapter
VirtualDiskAdapter
```

This allows agents to develop independently.

For example:

```text
Recovery Engine
      ↓
VirtualDiskAdapter
```

can be developed before:

```text
Recovery Engine
      ↓
PhysicalDeviceAdapter
```

---

# 20. No fake success

The agents must NEVER make the UI display:

```text
SANITIZATION SUCCESSFUL
```

unless the backend actually produced a successful result for the defined operation and verification scope.

Similarly, recovery must not display:

```text
100% recovered
```

unless the system has evidence supporting that claim.

Use:

```text
COMPLETED
VERIFIED
PARTIALLY VERIFIED
NOT VERIFIED
FAILED
UNSUPPORTED
```

with scope.

---

# 21. Agent prompts

## Agent A startup prompt

```text
You are Agent A for VANISH.

Read all files under /docs before coding.

You own device discovery, platform integration, safety gates, sanitization policy, sanitization adapters, targeted deletion, verification and audit.

Do not modify Agent B's forensic internals.

Build against common contracts.

Use simulation/mocks before physical hardware.

Never perform destructive operations on the host system disk.

Every task must include tests and documentation.

Before changing a shared contract, document the proposed change and ask for coordination.

At the end of every task report:
- files changed
- tests
- interfaces
- assumptions
- limitations
- integration requirements
```

## Agent B startup prompt

```text
You are Agent B for VANISH.

Read all files under /docs before coding.

You own read-only acquisition, filesystem analysis, raw scanning, carving, fragmented reconstruction, validation, recovered artifact metadata and recovery metrics.

Do not modify Agent A's device/sanitization internals.

Build first against virtual disk images.

Forensic sources must remain read-only.

Every recovered artifact needs provenance and validation status.

Do not claim recovery certainty beyond the evidence.

Before changing a shared contract, document the proposed change and coordinate.

At the end of every task report:
- files changed
- tests
- interfaces
- assumptions
- limitations
- integration requirements
```

---

# 22. Daily workflow

## Start of session

Both developers:

```bash
git checkout main
git pull
git checkout <feature-branch>
git rebase main
```

Then check:

```text
GitHub Issues
WORK_STATUS.md
Open PRs
Contract changes
```

## During work

```text
Issue
 ↓
Agent implementation
 ↓
tests
 ↓
commit
 ↓
push
```

## End of session

Update:

```text
docs/WORK_STATUS.md
```

Then push the branch.

---

# 23. Weekly integration

At least once per development cycle:

```text
Agent A branch
       +
Agent B branch
       ↓
Integration branch
       ↓
Full test suite
       ↓
Demo build
```

Do not wait until the final week to discover that both agents designed incompatible architectures.

---

# 24. Golden rule

The project is not:

```text
Agent A builds half
+
Agent B builds half
=
VANISH
```

It is:

```text
                VANISH
                   │
          ┌────────┴────────┐
          ↓                 ↓
      SANITIZE           RECOVER
          │                 │
          └────────┬────────┘
                   ↓
             VERIFY
                   ↓
               AUDIT
                   ↓
              REPORT
                   ↓
                  UI
```

The **integration layer is the actual product**.

The two agents are implementation teams, not two independent projects.

---

# 25. Final operating principle

Build VANISH like a systems product:

```text
Specification
     ↓
Contracts
     ↓
Modules
     ↓
Tests
     ↓
Integration
     ↓
Hardware
     ↓
Verification
     ↓
Evidence
```

Not:

```text
Prompt agent
 ↓
generate code
 ↓
hope it works
```

Agents are accelerators.

The architecture, safety model, interfaces, testing strategy and engineering decisions remain the team's responsibility.
