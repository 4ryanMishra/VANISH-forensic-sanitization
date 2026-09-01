# VANISH — Physical Laboratory (Revised: SanDisk-only, no laptop targets)

## Hardware reality

Available: one 16 GB SanDisk USB flash drive. No dedicated/disposable SSD
or NVMe device. Laptops (Aryan's and Subodeep's) are NOT to be used as
destructive targets under any circumstance — this is a hard rule, not a
default that gets relaxed under demo pressure.

This changes what "physical" can mean for this build. It does not change
what you can architect, simulate, or credibly demo — see below.

## What the SanDisk actually is

A generic USB flash drive. Per `01_MASTER_ENGINEERING_SPEC.md` §7:

> A generic USB flash drive is not automatically NVMe.

Treat it as: USB mass-storage class device, controller/FTL-managed
internally (some wear-leveling exists even on cheap flash), but with
**no exposed ATA SECURITY ERASE / SANITIZE DEVICE or NVMe Sanitize/Format
NVM command set** in the way a real NVMe SSD would have. Do not claim or
demo hardware-level Sanitize/Crypto Erase commands against it — you would
be lying about what the device supports, which `05_AGENT_RULES.md`
explicitly forbids ("do not invent device capabilities").

## What you CAN legitimately do on the SanDisk

- Filesystem-level experiments: create, delete, recover files (Subodeep's
  forensic pipeline — this is real, no caveats needed)
- Raw scanning and carving on real (if simple) flash-controller behavior
- Logical-level "deletion" workflows and observing what's actually still
  recoverable afterward — this is a genuinely good demo of "filesystem
  deletion ≠ sanitization" using real hardware, not a simulation
- A **software-level overwrite pass** (e.g., full-device overwrite via the
  host) as one sanitization *method option*, clearly labeled as overwrite,
  not as a hardware Sanitize command
- Controlled, disposable-content-only write tests

## What you CANNOT do on the SanDisk, and should not pretend to

- ATA/NVMe hardware Sanitize, Secure Erase, or Crypto Erase — the device
  doesn't expose these; do not implement an adapter that calls them and
  silently no-ops or fakes success
- Physical NAND-level verification claims — you have no way to desolder
  and inspect chips (that's literally what the Wei et al. FAST'11 paper
  had to do to verify anything at that level)

## SSD/NVMe-specific sanitization: simulation only

Per the existing execution modes in `01_MASTER_ENGINEERING_SPEC.md` §5,
build and demo the SSD/NVMe capability-discovery → command-selection →
execution-adapter path entirely in **Simulation mode** against mocked
device capability profiles (e.g., a mock device object that reports
`supports_nvme_sanitize: true`). This is not a downgrade — it's the
correct way to demonstrate capability-aware policy selection without
hardware you don't have, and it's honest about what's simulated vs. real,
which is exactly what `05_AGENT_RULES.md` and `09_DEMO_WORKFLOW.md` require
("clearly label simulations," "never improvise commands during a
demonstration").

For the pitch/demo narrative: present the SanDisk run as the real,
end-to-end proof (delete → recover → sanitize-via-overwrite →
re-attempt-recovery → audit/cert), and present the NVMe/SSD Sanitize path
as an architected-and-simulated capability, explicitly labeled as such on
screen. Judges respond better to "here's what's real and here's what's
architected for hardware we don't have access to" than to an implied claim
that gets caught under questioning.

## Boot environment

Deprioritized — Phase 9 in `10_IMPLEMENTATION_ROADMAP.md` (bootable Linux
live environment) requires either a spare machine or a VM. If pursued,
build and test it inside a VM, never on either team member's primary
laptop. Given the two-person team split, treat this as optional scope; it
strengthens the pitch's "isolated, no host OS interference" story but is
not required for a working demo.

## Before any write test on the SanDisk

Verify:
- device path
- model/vendor string
- capacity
- not the boot/system disk (should be trivially true here, but the
  safety-gate check should still run and log it — this is also good
  practice for demoing the safety gate itself)
- disposable contents only (never real personal files)

## If the team later gets access to a real SSD/NVMe device

Re-enable the original progression from the prior version of this doc:
virtual disk → disposable USB → dedicated disposable SSD/NVMe. Do not
retrofit claims about the SanDisk once real hardware is available —
keep the two hardware tiers (flash-only vs. NVMe-capable) clearly
separated in both code (capability discovery, not assumption) and demo
narrative.
