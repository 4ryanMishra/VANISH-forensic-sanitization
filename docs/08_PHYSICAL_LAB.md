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

## SSD/NVMe-specific sanitization: real command layer, simulated target

Per the existing execution modes in `01_MASTER_ENGINEERING_SPEC.md` §5,
build the actual NVMe/SSD hardware sanitize command layer in full: ATA
`SECURITY ERASE UNIT` / `SANITIZE DEVICE` subcommands, NVMe `Format NVM` /
`Sanitize` (Crypto Erase / Block Erase / Overwrite), capability discovery,
and policy selection between them. This is real, tested code — it is your
main technical differentiator and should not be stubbed out.

What's simulated is the *target device*, not the command logic: run this
layer in Simulation mode against a mocked device object (e.g. one that
reports `supports_nvme_sanitize: true` and returns a plausible completion
status), because no physical NVMe/SSD is available to issue these commands
against for real. This is a normal, defensible engineering position —
driver-level code is routinely validated against simulators before
hardware access — and it's consistent with `05_AGENT_RULES.md`'s
"clearly label simulations" and "do not invent device capabilities" rules:
the capability is real code, the device reporting that capability is mocked,
and both facts should be visible in the UI/demo, not blurred together.

For the pitch/demo narrative: present the SanDisk run as the real,
end-to-end proof (delete → recover → sanitize-via-overwrite →
re-attempt-recovery → audit/cert). Then show the NVMe/SSD Sanitize command
layer running live against the simulated target — same real code path,
clearly labeled as a simulated device — as your standout technical depth.
Say plainly on screen which part is physical and which is simulated;
judges respond far better to precise honesty about scope than to an
implied claim that gets caught under questioning.

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
