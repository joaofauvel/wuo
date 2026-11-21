# Full feature upgrade boot handoff

## Goal

Keep `wuo update` and **Troubleshoot → wuo** for full Windows feature upgrades that keep apps and data. Support ordinary installs and installs with a separate EFI partition, a third-party boot manager, or selected hooks with boot-time requirements. The upgrade mechanism must work across supported source and target builds and must discover volumes independently of their Windows drive letters.

## Approaches

1. **Native Setup with a recovery handoff where required.** Keep native Setup for ordinary jobs. Require a durable recovery handoff when a selected hook must run offline before target boot or when the requested boot preservation cannot be enforced by the native path. This is the selected approach. It keeps routine installs on Microsoft's boot sequence and makes the protection a property of the job.
2. **Recovery handoff for every full upgrade.** A single boot sequence would simplify some testing but would make even a standard upgrade dependent on custom recovery and firmware changes.
3. **Native Setup callbacks alone.** Use documented callbacks for phases they actually provide. The pre-commit callback is before the offline phase. A completion callback is already too late for a boot dependency. The earlier lab also demonstrated that a SafeOS wrapper and a scratch EFI store, used alone, can be bypassed on cold restart.

See [Microsoft's feature update custom actions](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-enable-custom-actions) and [the earlier lab results](2026-11-19-full-feature-upgrade-rc.md#release-evidence).

## Job behavior

- Capture selected official, local, and third-party profiles with their revision or content digest. Show the selected profiles, the phase each action requires, and the boot protection the job will use. Describe any unsupported action or unmet prerequisite before committing.
- Give each supported hook a defined phase, target, and success condition. For a required offline action, resolve the replacement Windows installation and the control set it will use, apply the action, then read back the expected result. A callback receipt alone cannot authorize boot. For full upgrades, treat existing profile `post` registry hooks as required offline actions against the replacement installation. This default lets existing profiles keep their meaning without requiring edits. Clarify the target and timing at staging.
- Track the Windows, recovery, and EFI volumes by durable identity. Validate the firmware boot path and relevant fallback loader for jobs with preservation enabled. Leave the caller's requested EFI and firmware settings intact at the end of successful completion or recovery.
- Keep the replacement OS behind a verified recovery handoff until all required checks pass. The handoff must survive the reboots Setup schedules, unexpected restarts, and loss of power. A failure or ambiguous job state stays recoverable and shows the last completed step. Automatic continuation requires checks to pass against the current job and target.
- Retain the existing opt-in backup drive behavior. Validate a supplied destination before committing. When starting without backup, retain explicit confirmation about the available recovery options. Access to the independent recovery route is required for protected jobs even when a backup was declined.
- Preserve logs and the identifiers needed to diagnose or recover a failed job. Publish a full-upgrade candidate only for configurations with passing evidence. Keep the local guard in place until it can be replaced by the verified handoff.

## Validation

1. Instrument a full upgrade from clean 25H2 to 26H2 in a disposable guest. Record OS volume identity, the running and replacement SYSTEM hives and selected control sets, relevant driver and override values, BCD entries, and persistent UEFI order at the Setup reboot boundaries. Record final build and survival of an app and user-data fixture. Use an immutable base and retain logs separately.
2. Prove candidate handoff behavior independently of the hypervisor's ability to pause the guest. Rehearse a full upgrade with EFI and Windows on the same disk and on different disks, with and without hooks. Include a valid hook, a rejected hook, an unreadable or wrong target, and an unexpected cold restart. Check signed boot behavior for any configuration that claims Secure Boot support.
3. Demonstrate the rejected state by restarting and confirming recovery runs before replacement Windows. Restore a verified backup, then check that the original build, data, EFI fallback file, and selected boot order are back. Preserve the protected failure state when a backup is unavailable.
4. On a disposable physical Windows install inside a USB4 enclosure, exercise successful and failed protected upgrades before relying on the path on a daily-use external Windows install. The PCIe/NVMe mock covers the driver failure pattern. USB4 routers and the firmware handoff require hardware.
5. Exercise explicitly supplied ISO media and any full source obtained from a Windows Update offer. An offer routed through the proven Setup backend must satisfy the same prerequisites. An offer that cannot be acquired or controlled by that backend remains visible as unavailable for automatic full upgrade. Keep enablement packages on their independently validated servicing route.

The implementation remains open until the lab identifies a recovery boundary that Setup cannot bypass. The first experiment records the boundary using host-side observation. A hypervisor pause is an observation tool and cannot serve as evidence for the product handoff.
