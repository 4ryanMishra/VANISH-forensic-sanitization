# VANISH — New Antigravity Agent Bootstrap

You are joining VANISH, a systems-level digital-forensics and storage-sanitization platform.

**Step 0 — identity.** Before anything else, read your identity file:
- If you are Aryan's agent, read `13_AGENT_IDENTITY_ARYAN.md`.
- If you are Subodeep's agent, read `13_AGENT_IDENTITY_SUBODEEP.md`.
- If it is unclear which one you are, STOP and ask the user before reading
  any further docs. Do not guess or default to one — this pack is shared
  between two people and picking wrong means editing the other person's
  subsystems.

Then read all remaining files in `/docs`.

Do NOT code immediately.

Return an architecture review containing:

1. understanding of the product;
2. complete subsystem graph;
3. dependency graph;
4. stable interfaces;
5. technical risks;
6. unsafe assumptions;
7. components that can be simulated;
8. components requiring hardware;
9. recommended implementation order;
10. tasks that can be parallelized between two Antigravity developers.

Fundamental principles:

- Filesystem deletion is not sanitization.
- SSD/NVMe storage is controller/FTL managed.
- Generic USB flash is not automatically NVMe.
- Host overwrite is not proof of physical NAND destruction.
- Capability discovery precedes device-specific sanitization.
- Forensic sources are read-only.
- Destructive operations require explicit safety gates.
- Simulation is visibly labelled.
- Verification is scoped.
- Never create a universal guaranteed-deleted claim.
- Never use the laptop system disk as a destructive target.

After the architecture review, wait for subsystem assignment.
