# Remote Attestation with vTPM (vSphere Virtual TPM)

## Overview

Remote attestation allows the bootstrap server to verify that an agent is running
on a known-good system image before approving enrollment. This is done using
TPM 2.0 Platform Configuration Registers (PCRs), which record a cryptographic
chain of every component that participated in the boot process.

In a vSphere environment, each VM can be provisioned with a **Virtual TPM (vTPM)**
backed by the host's key provider (vSphere Native Key Provider, KMS, or
vSphere Trust Authority). The vTPM behaves identically to a hardware TPM 2.0
from the guest OS perspective, including PCR measurements and remote attestation.

## How PCR Measurements Work

PCRs are extend-only registers. Each boot stage measures the next component
before handing off control:

```
PCR_new = SHA256(PCR_old || measurement)
```

Because the operation is a hash chain, the final PCR value is deterministic:
identical firmware + bootloader + kernel + initrd will always produce the same
PCR values.

## PCR Register Map

| PCR   | What It Measures                        | Changes When                          |
|-------|-----------------------------------------|---------------------------------------|
| 0     | Firmware code (UEFI)                    | Firmware update                       |
| 1     | Firmware configuration (UEFI settings)  | BIOS/UEFI setting change              |
| 2     | Option ROMs / additional firmware       | Hardware or driver change             |
| 3     | Option ROM configuration                | Option ROM setting change             |
| 4     | Boot loader code (GRUB, shim)           | Boot loader update                    |
| 5     | Boot loader configuration (grub.cfg)    | GRUB config change                    |
| 7     | Secure Boot policy (PK, KEK, db, dbx)  | Secure Boot key enrollment/revocation |
| 8-9   | Kernel and initrd (GRUB-measured)       | Kernel or initramfs update            |
| 10    | IMA (runtime file integrity)            | Any measured file access              |
| 11-14 | Application-defined                     | Application-specific                  |

### PCRs Most Relevant for Image Verification

For verifying a VM is running a specific image, focus on:

- **PCR 0, 1** -- Firmware identity and configuration
- **PCR 4** -- Boot loader identity
- **PCR 7** -- Secure Boot state (ensures only signed kernels boot)
- **PCR 8, 9** -- Kernel and initramfs identity

PCR 10 (IMA) is useful for runtime integrity monitoring but changes with every
measured file access, making it impractical as a static baseline.

## vSphere vTPM Specifics

### Prerequisites

- vSphere 6.7+ (7.0+ recommended for full TPM 2.0 support)
- A key provider configured on the vCenter (vSphere Native Key Provider, external
  KMS, or vSphere Trust Authority)
- VM hardware version 14+
- VM encryption is NOT required -- the vTPM only requires a key provider for
  sealing its own state
- EFI firmware (not BIOS) must be selected for the VM

### How vSphere vTPM Differs from Hardware TPM

| Aspect              | Hardware TPM                  | vSphere vTPM                         |
|---------------------|-------------------------------|--------------------------------------|
| PCR measurements    | Identical behavior            | Identical behavior                   |
| Endorsement Key     | Burned into hardware          | Generated per-VM by vCenter          |
| Attestation Key     | Derived from EK              | Derived from EK (same flow)          |
| Lifecycle           | Tied to physical motherboard  | Tied to VM; migrates with vMotion    |
| Firmware PCRs (0-1) | Physical UEFI firmware        | vSphere virtual UEFI firmware        |
| Cloning             | Not possible                  | Cloned VMs get a **new** vTPM        |

Key implication: when you clone a VM template, each clone gets a unique vTPM
with unique keys. The PCR values, however, will be **identical across clones**
as long as the image (firmware + bootloader + kernel + initrd) is the same.
This is exactly what makes golden-image verification work.

### Enabling vTPM on a VM

1. Ensure a key provider is configured in vCenter
2. Edit VM settings > Add New Device > Trusted Platform Module
3. The guest OS will see `/dev/tpm0` (Linux) or a TPM 2.0 device (Windows)

## Establishing a Golden Image Baseline

### Step 1: Build the Reference Image

Create your VM template with the exact OS, kernel, and bootloader you intend
to deploy. This is your golden image.

### Step 2: Boot and Capture PCR Values

Deploy a VM from the template with a vTPM enabled. After boot, capture the
PCR values from inside the guest:

```bash
# Read the PCRs relevant for image verification
tpm2_pcrread sha256:0,1,4,7,8,9

# Example output:
#   sha256:
#     0 : 0xA3B1C4D5E6F7...
#     1 : 0x1234567890AB...
#     4 : 0xBBCCDDEEFF00...
#     7 : 0x9988776655443...
#     8 : 0xAABBCCDDEEFF...
#     9 : 0x112233445566...
```

Alternatively, read PCRs programmatically using the `go-tpm` library:

```go
rw, err := tpm2.OpenTPM("/dev/tpm0")
if err != nil {
    log.Fatal(err)
}
defer rw.Close()

pcrSelection := tpm2.PCRSelection{
    Hash: tpm2.AlgSHA256,
    PCRs: []int{0, 1, 4, 7, 8, 9},
}
pcrValues, err := tpm2.ReadPCRs(rw, pcrSelection)
```

### Step 3: Record as Policy

Save the captured PCR values as the expected baseline for this image version.
A practical format:

```json
{
  "image": "ubuntu-22.04-base-v3",
  "captured": "2026-03-25T12:00:00Z",
  "pcr_bank": "sha256",
  "pcrs": {
    "0": "a3b1c4d5e6f7...",
    "1": "1234567890ab...",
    "4": "bbccddeeff00...",
    "7": "9988776655443...",
    "8": "aabbccddeeff...",
    "9": "112233445566..."
  }
}
```

### Step 4: Update Baseline on Image Changes

Any change that affects the measured components requires a new baseline capture:

- **Firmware update** -- recapture PCR 0, 1
- **Kernel or initramfs update** -- recapture PCR 8, 9
- **Boot loader update** -- recapture PCR 4
- **Secure Boot key change** -- recapture PCR 7

Integrate baseline capture into your image build pipeline:
build image -> boot in CI -> capture PCRs -> publish baseline alongside the image.

## Attestation Flow

During bootstrap enrollment, the attestation flow is:

```
   Agent (VM)                          Bootstrap Server
      |                                       |
      |  1. Request bootstrap                 |
      |-------------------------------------->|
      |                                       |
      |  2. Nonce challenge                   |
      |<--------------------------------------|
      |                                       |
      |  3. TPM Quote (PCRs + nonce,          |
      |     signed by Attestation Key)        |
      |-------------------------------------->|
      |                                       |
      |  4. Verify:                           |
      |     a. Quote signature is valid       |
      |     b. Nonce matches                  |
      |     c. PCR values match golden image  |
      |                                       |
      |  5. Approve / Deny                    |
      |<--------------------------------------|
```

### What the Server Verifies

1. **Quote authenticity** -- The TPM Quote is signed by an Attestation Key (AK)
   that chains back to the vTPM's Endorsement Key. This proves the PCR values
   came from a real (v)TPM, not fabricated by software.

2. **Freshness** -- The server-provided nonce is included in the signed quote,
   preventing replay attacks.

3. **Image identity** -- The quoted PCR values are compared against the golden
   baseline for the expected image. A mismatch means the VM booted a different
   firmware, kernel, or bootloader than expected.

## Practical Considerations

### What PCR Mismatches Mean

| Mismatched PCR | Likely Cause                                       |
|----------------|----------------------------------------------------|
| 0 or 1         | Different firmware version or UEFI settings         |
| 4              | Different bootloader (GRUB version, shim)           |
| 7              | Secure Boot disabled or different key set           |
| 8 or 9         | Different kernel or initramfs                       |
| Multiple       | Entirely different image or major update             |

### Managing Multiple Image Versions

In practice you will have several active image versions at any time. Maintain
a policy table mapping image identifiers to their expected PCR baselines:

| Image Version          | PCR 0      | PCR 4      | PCR 7      | PCR 8      | Status  |
|------------------------|------------|------------|------------|------------|---------|
| ubuntu-22.04-base-v3   | a3b1c4...  | bbccdd...  | 998877...  | aabbcc...  | active  |
| ubuntu-22.04-base-v2   | a3b1c4...  | bbccdd...  | 998877...  | 77ff88...  | active  |
| ubuntu-22.04-base-v1   | a3b1c4...  | aa1122...  | 998877...  | 55ee99...  | retired |

### vMotion and DRS

vSphere vTPM state migrates transparently with vMotion. PCR values are
preserved across host migrations -- no re-attestation is needed after a
vMotion event.

### Snapshot and Revert

Reverting a VM to a snapshot also reverts the vTPM state, including PCR
registers. The PCR values after revert will match the snapshot point, which
should still match the golden baseline for that image version (assuming no
changes were made between snapshot and boot measurement).

### Template Cloning

When you clone a VM or deploy from a template:

- A **new vTPM** is created with unique Endorsement and Attestation Keys
- PCR values after first boot will match the template's baseline (same image)
- The Endorsement Key will be different (unique VM identity)

This means you cannot use the EK to pre-register specific VMs, but you can
use PCR-based attestation to verify any clone is running the expected image.

## Anti-Proxy Attack: vSphere EK Binding

### The Problem

A rogue VM on the same vCenter with a valid vTPM and the same golden image
could pass all standard attestation checks (valid AK cert from the same CA,
matching PCR values). The TPM quote is cryptographically valid but comes from
the wrong VM.

### The Solution

vCenter generates and provisions each vTPM's Endorsement Key (EK). The EK is
unique per VM and available through the vSphere API via
`VirtualTPM.EndorsementKeyCertificate`. By cross-referencing the EK certificate
presented by the agent during attestation against the EK certificate vSphere
reports for the VM at that IP, the bootstrap server can verify that the TPM
quote was generated by the specific vTPM belonging to the expected VM.

### Detection Logic

```
Bootstrap request from IP X
    |
    v
vSphere configured?
    NO  --> Standard TPM verification only (physical box or no vSphere)
    YES --> LookupVMByIP(X)
              |
              v
          Found in vCenter?
              NO  --> Not a vSphere VM --> standard TPM only
              YES --> vSphere VM --> apply EK binding verification
                        |
                        v
                    VM has vTPM with EK certs?
                        NO  --> warn or deny (configurable)
                        YES --> compare agent EK fingerprint vs vSphere EK fingerprint
                                  MATCH    --> vTPM identity confirmed
                                  MISMATCH --> DENIED (possible proxy attack)
```

### Configuration

Add to `config.json` to enable vSphere EK binding:

```json
{
  "vsphere_addr": "vcenter.example.com",
  "vsphere_username": "readonly-user@vsphere.local",
  "vsphere_password_file": "/etc/bootstrap/vsphere-password.txt",
  "vsphere_datacenter": "DC1",
  "vsphere_skip_verify": false,
  "vsphere_ek_binding": true,
  "vsphere_require_ek": false,
  "vsphere_cache_ttl": "5m"
}
```

| Setting | Description |
|---------|-------------|
| `vsphere_addr` | vCenter FQDN or IP. Empty disables vSphere integration entirely. |
| `vsphere_ek_binding` | Enable EK fingerprint verification for VMs found in vCenter. |
| `vsphere_require_ek` | When true, deny attestation if vSphere cannot provide EK data or agent omits EK cert. When false, log a warning and continue. |
| `vsphere_cache_ttl` | How long to cache VM lookups (default 5 minutes). |

### Attack Coverage

| Attack Scenario | Defense |
|----------------|---------|
| Rogue VM presents own vTPM quote | EK fingerprint won't match vSphere-known EK for that IP's VM |
| Proxy forwards challenge to real VM | Source IP binding -- challenge tied to requester IP |
| Rogue VM spoofs EK cert in quote | vSphere is the authority -- rogue cannot change what vCenter reports |
| Same golden image, different VM | EK fingerprint is per-VM even with identical OS/PCRs |

### Physical Machines

When a bootstrap request comes from an IP not found in vCenter inventory, the
server assumes it is a physical machine (or unmanaged VM) and skips EK binding.
Standard TPM attestation (quote signature, nonce, PCR verification) still
applies. Physical TPM anti-proxy measures (EK pre-registration, manufacturer
CA validation) are a future enhancement.

## References

- [TPM 2.0 Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [vSphere Virtual TPM Documentation](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-6F811A7A-D58B-47B4-84B4-6AF4BE6E9EC6.html)
- [Linux IMA (Integrity Measurement Architecture)](https://sourceforge.net/p/linux-ima/wiki/Home/)
- [go-tpm Library](https://github.com/google/go-tpm)
