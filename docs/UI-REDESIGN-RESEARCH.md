# Native redesign research: 7 November 2026

## Decision

Keep the executable Rust control plane and use eframe/egui 0.37 with wgpu 30,
WGSL and an indexed, depth-tested armor mesh. Native Vulkan/GLES avoids Linux
WebKitGTK's unavailable-by-default WebGPU path. Glow remains compatibility mode.
Three.js/R3F/Babylon/A-frame are alternative web scene stacks, not libraries to
pile into one native app. Motion's guidance informs interaction and companion CSS.

## Verified sources

- https://github.com/emilk/egui/blob/0.37.0/crates/egui_demo_app/src/apps/custom3d_wgpu.rs
- https://docs.rs/egui-wgpu/0.37.0/egui_wgpu/trait.CallbackTrait.html
- https://wgpu.rs/
- https://v2.tauri.app/reference/webview-versions/
- https://github.com/WebKit/WebKit/blob/webkitgtk-2.54.2/Source/cmake/WebKitFeatures.cmake
- https://motion.dev/docs/ai-kit-install
- https://motion.dev/docs/performance
- https://github.com/anthropics/skills/tree/main/skills/frontend-design
- https://github.com/pbakaus/impeccable (reviewed reference, no hooks/binary installer)
- https://github.com/IBM/plex (bundled, pinned OFL fonts)

Motion's free documentation MCP is project-local and connected. No paid Motion+
or 21st/Magic retrieval, keys, subscriptions or automatic installer hooks added.
The in-app browser exposed navigator.gpu but the Three.js example could not obtain
a usable WebGPU renderer: API presence is not device availability.

Safety policy, detector semantics, privileged helpers and system DNS stay separate
from presentation. Rendered checks, keyboard access and reduced motion govern QA;
visual polish is not evidence of improved detection or tamper resistance.

## Native integration trap

With `default-features = false`, explicitly enable eframe's `accesskit`,
`clipboard` and `links`. Widget metadata alone does not expose the native
accessibility tree; without `clipboard`, Copy actions use a simulated clipboard.
Source: https://docs.rs/eframe/0.37.0/eframe/#feature-flags
