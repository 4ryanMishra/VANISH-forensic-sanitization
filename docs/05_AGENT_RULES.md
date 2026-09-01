# VANISH — Antigravity Agent Rules

Before coding, read:
- 01_MASTER_ENGINEERING_SPEC.md
- 02_TECH_STACK.md
- 04_TEAM_SPLIT.md
- 06_API_CONTRACTS.md
- 07_TEST_STRATEGY.md

Rules:
- Do not redesign architecture silently.
- Do not implement destructive physical operations first.
- Develop against virtual images and mocks.
- Keep forensic source access read-only.
- Do not invent device capabilities.
- Clearly label simulations.
- Never expose universal recovery-impossibility claims.
- Add deterministic tests.
- Fail closed on ambiguous destructive targets.
- Never use the laptop system disk as a destructive target.
- Document assumptions and limitations.

Every completed task must report:

```text
Files changed:
Interfaces:
Tests added:
Tests run:
Assumptions:
Limitations:
Integration requirements:
```

A physical destructive adapter requires simulation, safety gates, identity checks, integration tests, review by both developers and disposable hardware before use.
