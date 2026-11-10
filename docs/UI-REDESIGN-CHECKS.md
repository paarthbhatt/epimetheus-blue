# Native redesign status

The first preview was rejected as too flat. The active task is a richer,
professional Overview and shared-frame prototype, with functional 3D layer
inspection and restrained navigation/state transitions. Design acceptance is
pending; do not call the redesign complete or publish it.

## Baseline checks before the second visual pass

- 215 Rust tests passed; strict release Clippy passed after triangle-chunk cleanup.
- Nine popup regression tests and the extension validator passed.
- Native wgpu/Vulkan rendering was observed on this workstation.
- Navigation was exercised through all eleven workspaces; reduced motion and
  the 900×620 logical layout were checked with an isolated state directory.
- Native clipboard, links and accessibility features were restored explicitly.
- Cua Driver and the HTTP fixture servers started for QA were stopped.

Prowl's repository index is unavailable. No indexed merge/security approval,
new release, real firewall activation, or cleanup deletion was performed.

Temporary screenshots and QA scripts live under `/tmp/opencode/`; do not treat
them as approved designs. The first-pass binaries are not the final visual design.

## Revised prototype

- Crowned/beveled armor with brushed-metal and clearcoat studio shading.
- Compact grouped navigation and inset frame; interruptible 180ms destination
  transitions, with immediate reduced-motion/lost-focus behavior.
- File/DNS/Integrity selection exposes that layer and shows its real reported
  scope and next action. No protection setting changes; picking is depth-aware.
- All 51 native UI tests passed; strict UI Clippy and formatting passed.
- Native Vulkan captures exercised the three inspections and reduced motion
  through a finite helper that stops its app and driver afterward.
- Screenshots: `/tmp/opencode/blue-premium-evidence/`. Design acceptance is still
  pending; no new installation or publication has been performed.
