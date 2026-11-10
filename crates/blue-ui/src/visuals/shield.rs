//! Depth-tested, beveled armor. No protection decisions or service calls.
use bytemuck::{Pod, Zeroable};
use eframe::egui::{self, Color32, FontId, Rect, Response, Sense, Stroke, Vec2};
use eframe::egui_wgpu::{self, wgpu};
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use wgpu::util::DeviceExt as _;

const SHADER: &str = include_str!("shield.wgsl");
const RESOLUTION: u32 = 640;
const SAMPLES: u32 = 4;
const CAMERA: [f32; 3] = [0.0, 0.06, 3.75];
const REST_YAW: f32 = -0.38;
const REST_PITCH: f32 = -0.10;
const FIELD_OF_VIEW: f32 = 42.0;
const CONTOUR_STEPS: usize = 24;
const BEVEL_STEPS: usize = 8;
const FACE_RINGS: usize = 8;
const HALF_THICKNESS: f32 = 0.095;
const BEVEL_RADIUS: f32 = 0.058;
const CROWN: f32 = 0.028;
const SCALES: [f32; 3] = [0.87, 0.99, 1.10];
const OFFSETS: [[f32; 3]; 3] = [
    [0.045, -0.022, 0.20],
    [0.0, 0.0, 0.0],
    [-0.048, 0.025, -0.20],
];
const INSPECTION_OFFSETS: [[[f32; 3]; 3]; 3] = [
    [
        [0.17, -0.02, 0.12],
        [-0.06, 0.0, -0.015],
        [-0.16, 0.03, -0.10],
    ],
    [
        [0.35, -0.04, 0.02],
        [-0.10, 0.055, 0.32],
        [-0.19, 0.0, -0.09],
    ],
    [
        [0.34, -0.05, -0.12],
        [0.12, 0.0, -0.10],
        [-0.22, 0.045, 0.60],
    ],
];
const INSPECTION_YAWS: [[f32; 3]; 3] =
    [[0.10, 0.025, 0.03], [0.04, 0.14, 0.06], [0.08, 0.045, 0.14]];
const BASE_COLORS: [[f32; 3]; 3] = [[0.255, 0.400, 1.0], [0.90, 0.93, 0.985], [0.36, 0.39, 0.55]];

type Mat4 = [[f32; 4]; 4];

fn multiply(a: Mat4, b: Mat4) -> Mat4 {
    let mut result = [[0.0; 4]; 4];
    for column in 0..4 {
        for row in 0..4 {
            result[column][row] = (0..4).map(|k| a[k][row] * b[column][k]).sum();
        }
    }
    result
}

fn transform(matrix: Mat4, point: [f32; 4]) -> [f32; 4] {
    std::array::from_fn(|row| (0..4).map(|k| matrix[k][row] * point[k]).sum())
}

fn rotation(yaw: f32, pitch: f32) -> Mat4 {
    let (sy, cy) = yaw.sin_cos();
    let (sx, cx) = pitch.sin_cos();
    multiply(
        [
            [cy, 0.0, -sy, 0.0],
            [0.0, 1.0, 0.0, 0.0],
            [sy, 0.0, cy, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ],
        [
            [1.0, 0.0, 0.0, 0.0],
            [0.0, cx, sx, 0.0],
            [0.0, -sx, cx, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ],
    )
}

fn translation(offset: [f32; 3]) -> Mat4 {
    [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [offset[0], offset[1], offset[2], 1.0],
    ]
}

fn view_projection(aspect: f32) -> Mat4 {
    let f = 1.0 / (FIELD_OF_VIEW.to_radians() * 0.5).tan();
    let (near, far) = (0.1, 12.0);
    let projection = [
        [f / aspect.max(0.1), 0.0, 0.0, 0.0],
        [0.0, f, 0.0, 0.0],
        [0.0, 0.0, far / (near - far), -1.0],
        [0.0, 0.0, near * far / (near - far), 0.0],
    ];
    let view = [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.0, 0.0, 1.0, 0.0],
        [-CAMERA[0], -CAMERA[1], -CAMERA[2], 1.0],
    ];
    multiply(projection, view)
}

fn sub(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    std::array::from_fn(|i| a[i] - b[i])
}
fn dot(a: [f32; 3], b: [f32; 3]) -> f32 {
    (0..3).map(|i| a[i] * b[i]).sum()
}
fn cross(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {
    [
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    ]
}
fn normalize(a: [f32; 3]) -> [f32; 3] {
    let length = dot(a, a).sqrt().max(0.000001);
    a.map(|value| value / length)
}
const PEARL: Color32 = Color32::from_rgb(239, 243, 255);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

const CONTOUR: [[[f32; 2]; 4]; 6] = [
    [[0.0, -0.97], [0.18, -0.97], [0.70, -0.39], [0.75, 0.10]],
    [[0.75, 0.10], [0.775, 0.345], [0.78, 0.67], [0.70, 0.77]],
    [[0.70, 0.77], [0.58, 0.92], [0.20, 0.94], [0.0, 0.94]],
    [[0.0, 0.94], [-0.20, 0.94], [-0.58, 0.92], [-0.70, 0.77]],
    [[-0.70, 0.77], [-0.78, 0.67], [-0.775, 0.345], [-0.75, 0.10]],
    [[-0.75, 0.10], [-0.70, -0.39], [-0.18, -0.97], [0.0, -0.97]],
];

#[derive(Clone, Copy)]
struct ContourPoint {
    position: [f32; 2],
    outward: [f32; 2],
}

fn contour() -> Vec<ContourPoint> {
    let mut points = Vec::with_capacity(CONTOUR.len() * CONTOUR_STEPS);
    for curve in CONTOUR {
        for step in 0..CONTOUR_STEPS {
            let t = step as f32 / CONTOUR_STEPS as f32;
            let s = 1.0 - t;
            let position = std::array::from_fn(|axis| {
                s * s * s * curve[0][axis]
                    + 3.0 * s * s * t * curve[1][axis]
                    + 3.0 * s * t * t * curve[2][axis]
                    + t * t * t * curve[3][axis]
            });
            let tangent: [f32; 2] = std::array::from_fn(|axis| {
                3.0 * s * s * (curve[1][axis] - curve[0][axis])
                    + 6.0 * s * t * (curve[2][axis] - curve[1][axis])
                    + 3.0 * t * t * (curve[3][axis] - curve[2][axis])
            });
            let length = tangent[0].hypot(tangent[1]).max(0.000001);
            points.push(ContourPoint {
                position,
                outward: [tangent[1] / length, -tangent[0] / length],
            });
        }
    }
    points
}

#[derive(Clone, Copy)]
struct Bounds {
    min: [f32; 3],
    max: [f32; 3],
}

impl Bounds {
    fn empty() -> Self {
        Self {
            min: [f32::INFINITY; 3],
            max: [f32::NEG_INFINITY; 3],
        }
    }

    fn include(&mut self, point: [f32; 3]) {
        for (axis, value) in point.into_iter().enumerate() {
            self.min[axis] = self.min[axis].min(value);
            self.max[axis] = self.max[axis].max(value);
        }
    }

    fn intersects(self, origin: [f32; 3], direction: [f32; 3], nearest: f32) -> bool {
        let mut near = 0.0_f32;
        let mut far = nearest;
        for axis in 0..3 {
            if direction[axis].abs() < 0.000001 {
                if origin[axis] < self.min[axis] || origin[axis] > self.max[axis] {
                    return false;
                }
                continue;
            }
            let a = (self.min[axis] - origin[axis]) / direction[axis];
            let b = (self.max[axis] - origin[axis]) / direction[axis];
            near = near.max(a.min(b));
            far = far.min(a.max(b));
            if near > far {
                return false;
            }
        }
        true
    }
}

struct MeshData {
    vertices: Vec<Vertex>,
    indices: Vec<u32>,
    layer_indices: [Range<usize>; 3],
    bounds: [Bounds; 3],
}

struct FallbackTriangle {
    indices: [u32; 3],
    depth: f32,
}

struct Fallback {
    source: MeshData,
    mesh: Arc<egui::Mesh>,
    triangles: Vec<FallbackTriangle>,
    depths: Vec<f32>,
    previous: Option<(Rect, Uniforms)>,
}

impl Fallback {
    fn new(source: MeshData) -> Self {
        Self {
            depths: vec![0.0; source.vertices.len()],
            triangles: Vec::with_capacity(source.indices.len() / 3),
            source,
            mesh: Arc::new(egui::Mesh::default()),
            previous: None,
        }
    }

    fn paint(&mut self, ui: &egui::Ui, rect: Rect, uniforms: Uniforms) {
        if self.previous != Some((rect, uniforms)) {
            let mesh = Arc::make_mut(&mut self.mesh);
            mesh.vertices.clear();
            mesh.indices.clear();
            append_shadow(mesh, rect);
            let base = mesh.vertices.len() as u32;
            for (index, vertex) in self.source.vertices.iter().enumerate() {
                let model = uniforms.models[vertex.layer as usize];
                let p = vertex.position;
                let world = transform(model, [p[0], p[1], p[2], 1.0]);
                let clip = transform(uniforms.view_projection, world);
                self.depths[index] = world[2];
                mesh.vertices.push(egui::epaint::Vertex {
                    pos: rect.center()
                        + egui::vec2(
                            clip[0] / clip[3] * rect.width() * 0.5,
                            -clip[1] / clip[3] * rect.height() * 0.5,
                        ),
                    uv: egui::epaint::WHITE_UV,
                    color: fallback_color(vertex, model, world, &uniforms),
                });
            }
            self.triangles.clear();
            for indices in self.source.indices.as_chunks::<3>().0 {
                let points: [egui::Pos2; 3] =
                    std::array::from_fn(|i| mesh.vertices[(base + indices[i]) as usize].pos);
                let a = points[1] - points[0];
                let b = points[2] - points[0];
                if a.x * b.y - a.y * b.x >= 0.0 {
                    continue;
                }
                self.triangles.push(FallbackTriangle {
                    indices: indices.map(|index| base + index),
                    depth: indices
                        .iter()
                        .map(|&i| self.depths[i as usize])
                        .sum::<f32>()
                        / 3.0,
                });
            }
            self.triangles.sort_by(|a, b| a.depth.total_cmp(&b.depth));
            for triangle in &self.triangles {
                mesh.indices.extend(triangle.indices);
            }
            self.previous = Some((rect, uniforms));
        }
        ui.painter().add(egui::Shape::Mesh(Arc::clone(&self.mesh)));
    }
}

fn fallback_color(vertex: &Vertex, model: Mat4, world: [f32; 4], uniforms: &Uniforms) -> Color32 {
    let n = vertex.normal;
    let normal = transform(model, [n[0], n[1], n[2], 0.0]);
    let normal = normalize([normal[0], normal[1], normal[2]]);
    let view = normalize(sub(CAMERA, [world[0], world[1], world[2]]));
    let key = normalize([-0.55, 0.8, 1.25]);
    let fill = normalize([0.9, 0.12, 0.8]);
    let highlight = dot(normal, normalize(std::array::from_fn(|i| key[i] + view[i])))
        .max(0.0)
        .powf(48.0);
    let layer = vertex.layer as usize;
    let (saturation, brightness) = match uniforms.states[layer] {
        1 => (1.0, 1.0),
        2 => (0.70, 0.91),
        0 => (0.16, 0.56),
        _ => (0.16, 0.74),
    };
    let base = BASE_COLORS[layer];
    let gray = dot(base, [0.2126, 0.7152, 0.0722]);
    let edge = vertex.surface[0].clamp(0.0, 1.0) * 0.68;
    let shade = 0.25
        + dot(normal, key).max(0.0) * 0.58
        + dot(normal, fill).max(0.0) * 0.16
        + uniforms.inspection[layer] * 0.04;
    let channels: [u8; 3] = std::array::from_fn(|i| {
        let color = (gray + (base[i] - gray) * saturation) * brightness;
        let color = color * (1.0 - edge) + BASE_COLORS[1][i] * edge * brightness;
        ((color * shade + highlight * 0.26) * 255.0).clamp(0.0, 255.0) as u8
    });
    Color32::from_rgb(channels[0], channels[1], channels[2])
}

fn append_shadow(mesh: &mut egui::Mesh, rect: Rect) {
    const STEPS: usize = 32;
    let center = egui::pos2(rect.center().x, rect.top() + rect.height() * 0.90);
    let radius = egui::vec2(rect.width() * 0.24, rect.height() * 0.029);
    let base = mesh.vertices.len() as u32;
    mesh.vertices.push(egui::epaint::Vertex {
        pos: center,
        uv: egui::epaint::WHITE_UV,
        color: Color32::from_black_alpha(48),
    });
    for (ring, (scale, alpha)) in [(0.35, 36), (0.70, 12), (1.0, 0)].into_iter().enumerate() {
        let start = mesh.vertices.len() as u32;
        for step in 0..STEPS {
            let angle = step as f32 / STEPS as f32 * std::f32::consts::TAU;
            mesh.vertices.push(egui::epaint::Vertex {
                pos: center + egui::vec2(angle.cos() * radius.x, angle.sin() * radius.y) * scale,
                uv: egui::epaint::WHITE_UV,
                color: Color32::from_black_alpha(alpha),
            });
        }
        for step in 0..STEPS as u32 {
            let next = (step + 1) % STEPS as u32;
            if ring == 0 {
                mesh.indices.extend([base, start + step, start + next]);
            } else {
                let previous = start - STEPS as u32;
                mesh.indices.extend([
                    previous + step,
                    start + step,
                    start + next,
                    previous + step,
                    start + next,
                    previous + next,
                ]);
            }
        }
    }
}

impl MeshData {
    fn new() -> Self {
        let outline = contour();
        let mut mesh = Self {
            vertices: Vec::with_capacity(12_000),
            indices: Vec::with_capacity(65_000),
            layer_indices: std::array::from_fn(|_| 0..0),
            bounds: [Bounds::empty(); 3],
        };
        for (layer, scale) in SCALES.into_iter().enumerate() {
            let first_vertex = mesh.vertices.len();
            let first_index = mesh.indices.len();
            mesh.front(layer as u32, scale, &outline);
            mesh.back(layer as u32, scale, &outline);
            mesh.rim(layer as u32, scale, &outline);
            mesh.layer_indices[layer] = first_index..mesh.indices.len();
            for vertex in &mesh.vertices[first_vertex..] {
                mesh.bounds[layer].include(vertex.position);
            }
        }
        mesh
    }

    fn front(&mut self, layer: u32, scale: f32, outline: &[ContourPoint]) {
        let base = self.vertices.len() as u32;
        self.vertices.push(Vertex {
            position: [0.0, 0.0, HALF_THICKNESS + CROWN],
            normal: [0.0, 0.0, 1.0],
            local: [0.0, 0.0],
            layer,
            surface: [0.0, 0.0],
        });
        let count = outline.len() as u32;
        for ring in 1..=FACE_RINGS {
            let radial = ring as f32 / FACE_RINGS as f32;
            let slope = -4.0 * CROWN * radial * (1.0 - radial * radial);
            let start = self.vertices.len() as u32;
            for point in outline {
                let boundary: [f32; 2] = std::array::from_fn(|axis| {
                    point.position[axis] - point.outward[axis] * BEVEL_RADIUS
                });
                let support =
                    (boundary[0] * point.outward[0] + boundary[1] * point.outward[1]) * scale;
                let local = boundary.map(|value| value * radial);
                self.vertices.push(Vertex {
                    position: [
                        local[0] * scale,
                        local[1] * scale,
                        HALF_THICKNESS + CROWN * (1.0 - radial * radial).powi(2),
                    ],
                    normal: normalize([
                        -slope * point.outward[0] / support,
                        -slope * point.outward[1] / support,
                        1.0,
                    ]),
                    local,
                    layer,
                    surface: [0.0, radial],
                });
            }
            for i in 0..count {
                let j = (i + 1) % count;
                if ring == 1 {
                    self.indices.extend([base, start + i, start + j]);
                } else {
                    self.connect(start - count + i, start + i, start + j, start - count + j);
                }
            }
        }
    }

    fn back(&mut self, layer: u32, scale: f32, outline: &[ContourPoint]) {
        let base = self.vertices.len() as u32;
        self.vertices.push(Vertex {
            position: [0.0, 0.0, -HALF_THICKNESS],
            normal: [0.0, 0.0, -1.0],
            local: [0.0, 0.0],
            layer,
            surface: [0.0, 0.0],
        });
        for point in outline {
            let local: [f32; 2] = std::array::from_fn(|axis| {
                point.position[axis] - point.outward[axis] * BEVEL_RADIUS
            });
            self.vertices.push(Vertex {
                position: [local[0] * scale, local[1] * scale, -HALF_THICKNESS],
                normal: [0.0, 0.0, -1.0],
                local,
                layer,
                surface: [0.0, 1.0],
            });
        }
        for i in 0..outline.len() as u32 {
            let a = base + 1 + i;
            let b = base + 1 + (i + 1) % outline.len() as u32;
            self.indices.extend([base, b, a]);
        }
    }

    fn rim(&mut self, layer: u32, scale: f32, outline: &[ContourPoint]) {
        let base = self.vertices.len() as u32;
        let count = outline.len() as u32;
        for back in [false, true] {
            let sign = if back { -1.0 } else { 1.0 };
            for step in 0..=BEVEL_STEPS {
                let t = step as f32 / BEVEL_STEPS as f32;
                let angle = if back { t } else { 1.0 - t } * std::f32::consts::FRAC_PI_2;
                let (sine, cosine) = angle.sin_cos();
                let cosine = cosine.max(0.0);
                let inset = BEVEL_RADIUS * (1.0 - cosine);
                let z = sign * (HALF_THICKNESS - BEVEL_RADIUS + BEVEL_RADIUS * sine);
                for point in outline {
                    let local: [f32; 2] = std::array::from_fn(|axis| {
                        point.position[axis] - point.outward[axis] * inset
                    });
                    self.vertices.push(Vertex {
                        position: [local[0] * scale, local[1] * scale, z],
                        normal: normalize([
                            point.outward[0] * cosine / scale,
                            point.outward[1] * cosine / scale,
                            sign * sine,
                        ]),
                        local,
                        layer,
                        surface: [cosine, 1.0],
                    });
                }
            }
        }
        for ring in 0..2 * (BEVEL_STEPS + 1) - 1 {
            let front = base + ring as u32 * count;
            let back = front + count;
            for i in 0..count {
                let j = (i + 1) % count;
                self.connect(front + i, back + i, back + j, front + j);
            }
        }
    }

    fn connect(&mut self, a: u32, b: u32, c: u32, d: u32) {
        self.indices.extend([a, b, c, a, c, d]);
    }

    fn pick(&self, rect: Rect, models: [Mat4; 3], pointer: egui::Pos2) -> Option<ShieldLayer> {
        if !rect.contains(pointer) || rect.width() <= 1.0 || rect.height() <= 1.0 {
            return None;
        }
        let f = 1.0 / (FIELD_OF_VIEW.to_radians() * 0.5).tan();
        let ndc = (pointer - rect.center()) / (rect.size() * 0.5);
        let direction = normalize([
            ndc.x * (rect.width() / rect.height()).max(0.1) / f,
            -ndc.y / f,
            -1.0,
        ]);
        let mut nearest = f32::INFINITY;
        let mut picked = None;
        for (layer, model) in models.into_iter().enumerate() {
            let delta = sub(CAMERA, [model[3][0], model[3][1], model[3][2]]);
            let origin = std::array::from_fn(|axis| {
                dot(delta, [model[axis][0], model[axis][1], model[axis][2]])
            });
            let ray = std::array::from_fn(|axis| {
                dot(direction, [model[axis][0], model[axis][1], model[axis][2]])
            });
            if !self.bounds[layer].intersects(origin, ray, nearest) {
                continue;
            }
            for indices in self.indices[self.layer_indices[layer].clone()]
                .as_chunks::<3>()
                .0
            {
                let points = indices.map(|index| self.vertices[index as usize].position);
                if let Some(distance) = ray_triangle(origin, ray, points) {
                    if distance < nearest {
                        nearest = distance;
                        picked = Some(ShieldLayer::ALL[layer]);
                    }
                }
            }
        }
        picked
    }
}

fn ray_triangle(origin: [f32; 3], direction: [f32; 3], points: [[f32; 3]; 3]) -> Option<f32> {
    let a = sub(points[1], points[0]);
    let b = sub(points[2], points[0]);
    let p = cross(direction, b);
    let determinant = dot(a, p);
    if determinant <= 0.00000001 {
        return None;
    }
    let t = sub(origin, points[0]);
    let u = dot(t, p) / determinant;
    if !(-0.00001..=1.00001).contains(&u) {
        return None;
    }
    let q = cross(t, a);
    let v = dot(direction, q) / determinant;
    if v < -0.00001 || u + v > 1.00001 {
        return None;
    }
    let distance = dot(b, q) / determinant;
    (distance > 0.0).then_some(distance)
}

fn footer_height(width: f32) -> f32 {
    if width < 210.0 {
        108.0
    } else {
        48.0
    }
}

fn shield_layout(rect: Rect) -> (Rect, [Rect; 3]) {
    let scene = Rect::from_min_max(
        rect.min,
        egui::pos2(rect.right(), rect.bottom() - footer_height(rect.width())),
    );
    let labels = std::array::from_fn(|index| {
        if rect.width() < 210.0 {
            Rect::from_min_size(
                egui::pos2(rect.left(), scene.bottom() + index as f32 * 36.0),
                egui::vec2(rect.width(), 36.0),
            )
        } else {
            Rect::from_min_size(
                egui::pos2(
                    rect.left() + index as f32 * rect.width() / 3.0,
                    scene.bottom(),
                ),
                egui::vec2(rect.width() / 3.0, 48.0),
            )
        }
    });
    (scene, labels)
}

fn paint_labels(
    ui: &egui::Ui,
    labels: [Rect; 3],
    responses: &[Response; 3],
    state: ShieldState,
    inspected: Option<ShieldLayer>,
) {
    for (index, (rect, layer)) in labels
        .into_iter()
        .zip([state.files, state.dns, state.integrity])
        .enumerate()
    {
        let selected = inspected == Some(ShieldLayer::ALL[index]);
        let response = &responses[index];
        let color = if selected || response.hovered() {
            PEARL
        } else {
            PEARL.gamma_multiply(0.80)
        };
        let vertical = rect.height() == 36.0;
        let (name_pos, name_align, state_pos, state_align) = if vertical {
            (
                egui::pos2(rect.left() + 12.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                egui::pos2(rect.right() - 12.0, rect.center().y),
                egui::Align2::RIGHT_CENTER,
            )
        } else {
            (
                egui::pos2(rect.center().x, rect.top() + 7.0),
                egui::Align2::CENTER_TOP,
                egui::pos2(rect.center().x, rect.top() + 26.0),
                egui::Align2::CENTER_TOP,
            )
        };
        ui.painter().text(
            name_pos,
            name_align,
            ShieldLayer::ALL[index].label(),
            FontId::proportional(13.0),
            color,
        );
        ui.painter().text(
            state_pos,
            state_align,
            layer.label(),
            FontId::proportional(11.5),
            layer.color(),
        );
        if selected {
            let (a, b) = if vertical {
                (
                    rect.left_top() + egui::vec2(3.0, 9.0),
                    rect.left_bottom() + egui::vec2(3.0, -9.0),
                )
            } else {
                (
                    egui::pos2(rect.center().x - 18.0, rect.top() + 1.0),
                    egui::pos2(rect.center().x + 18.0, rect.top() + 1.0),
                )
            };
            ui.painter()
                .line_segment([a, b], Stroke::new(2.0, Color32::from_rgb(65, 102, 255)));
        }
        if response.has_focus() {
            ui.painter().rect_stroke(
                rect.shrink(2.0),
                5.0,
                Stroke::new(1.3, PEARL),
                egui::StrokeKind::Inside,
            );
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
struct Uniforms {
    models: [Mat4; 3],
    view_projection: [[f32; 4]; 4],
    camera_phase: [f32; 4],
    states: [u32; 4],
    inspection: [f32; 4],
}

impl Uniforms {
    fn new(
        rect: Rect,
        state: ShieldState,
        motion: &Motion,
        animate: bool,
        hovered: Option<ShieldLayer>,
    ) -> Self {
        Self {
            models: motion.models(),
            view_projection: view_projection(rect.width() / rect.height().max(1.0)),
            camera_phase: [CAMERA[0], CAMERA[1], CAMERA[2], motion.phase],
            states: [
                state.files as u32,
                state.dns as u32,
                state.integrity as u32,
                u32::from(state.scanning && animate),
            ],
            inspection: [
                motion.layers[0],
                motion.layers[1],
                motion.layers[2],
                hovered.map_or(0.0, |layer| layer as u32 as f32 + 1.0),
            ],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
struct Vertex {
    position: [f32; 3],
    normal: [f32; 3],
    local: [f32; 2],
    layer: u32,
    surface: [f32; 2],
}

#[derive(Default)]
struct ResourceStore(HashMap<u64, GpuResources>);

struct GpuHandle {
    id: u64,
    texture: egui::TextureId,
    renderer: Arc<egui::mutex::RwLock<egui_wgpu::Renderer>>,
}

impl Drop for GpuHandle {
    fn drop(&mut self) {
        let mut renderer = self.renderer.write();
        renderer.free_texture(&self.texture);
        if let Some(store) = renderer.callback_resources.get_mut::<ResourceStore>() {
            store.0.remove(&self.id);
        }
    }
}

struct ShieldCallback {
    id: u64,
    uniforms: Uniforms,
}

impl egui_wgpu::CallbackTrait for ShieldCallback {
    fn prepare(
        &self,
        _device: &wgpu::Device,
        queue: &wgpu::Queue,
        _screen: &egui_wgpu::ScreenDescriptor,
        encoder: &mut wgpu::CommandEncoder,
        resources: &mut egui_wgpu::CallbackResources,
    ) -> Vec<wgpu::CommandBuffer> {
        if let Some(gpu) = resources
            .get_mut::<ResourceStore>()
            .and_then(|store| store.0.get_mut(&self.id))
        {
            if gpu.previous != Some(self.uniforms) {
                queue.write_buffer(&gpu.uniform_buffer, 0, bytemuck::bytes_of(&self.uniforms));
                gpu.render(encoder);
                gpu.previous = Some(self.uniforms);
            }
        }
        Vec::new()
    }

    fn paint(
        &self,
        _info: egui::PaintCallbackInfo,
        _pass: &mut wgpu::RenderPass<'static>,
        _resources: &egui_wgpu::CallbackResources,
    ) {
        // Egui's image pipeline composites the prepared texture. This avoids
        // coupling our depth/MSAA formats to the application's main render pass.
    }
}

struct GpuResources {
    scene_pipeline: wgpu::RenderPipeline,
    composite_pipeline: wgpu::RenderPipeline,
    vertices: wgpu::Buffer,
    indices: wgpu::Buffer,
    index_count: u32,
    uniform_buffer: wgpu::Buffer,
    scene_group: wgpu::BindGroup,
    composite_group: wgpu::BindGroup,
    scene_view: wgpu::TextureView,
    resolve_view: wgpu::TextureView,
    depth_view: wgpu::TextureView,
    output_view: wgpu::TextureView,
    previous: Option<Uniforms>,
}

impl GpuResources {
    fn new(device: &wgpu::Device, mesh: &MeshData) -> Self {
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Blue armor WGSL"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let scene_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("Blue armor uniform layout"),
            entries: &[wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::VERTEX_FRAGMENT,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(std::mem::size_of::<Uniforms>() as u64),
                },
                count: None,
            }],
        });
        let uniform_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Blue armor uniforms"),
            contents: bytemuck::bytes_of(&Uniforms::zeroed()),
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        });
        let scene_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Blue armor uniforms"),
            layout: &scene_layout,
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: uniform_buffer.as_entire_binding(),
            }],
        });
        let scene_view = target(
            device,
            "Blue armor MSAA",
            wgpu::TextureFormat::Rgba8Unorm,
            SAMPLES,
            false,
        );
        let resolve_view = target(
            device,
            "Blue armor linear resolve",
            wgpu::TextureFormat::Rgba8Unorm,
            1,
            true,
        );
        let depth_view = target(
            device,
            "Blue armor depth",
            wgpu::TextureFormat::Depth24Plus,
            SAMPLES,
            false,
        );
        let output_view = target(
            device,
            "Blue armor egui gamma output",
            wgpu::TextureFormat::Rgba8Unorm,
            1,
            true,
        );
        let composite_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("Blue armor composite layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("Blue armor resolve sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        let composite_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("Blue armor resolve texture"),
            layout: &composite_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: wgpu::BindingResource::TextureView(&resolve_view),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: wgpu::BindingResource::Sampler(&sampler),
                },
            ],
        });
        let scene_pipeline_layout =
            device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                label: Some("Blue armor scene layout"),
                bind_group_layouts: &[Some(&scene_layout)],
                immediate_size: 0,
            });
        let composite_pipeline_layout =
            device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                label: Some("Blue armor composite pipeline layout"),
                bind_group_layouts: &[Some(&composite_layout)],
                immediate_size: 0,
            });
        let scene_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("Blue armor beveled mesh"), layout: Some(&scene_pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader, entry_point: Some("vs_shield"),
                compilation_options: Default::default(),
                buffers: &[Some(wgpu::VertexBufferLayout {
                    array_stride: std::mem::size_of::<Vertex>() as u64,
                    step_mode: wgpu::VertexStepMode::Vertex,
                    attributes: &wgpu::vertex_attr_array![0 => Float32x3, 1 => Float32x3, 2 => Float32x2, 3 => Uint32, 4 => Float32x2],
                })],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader, entry_point: Some("fs_shield"), compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: wgpu::TextureFormat::Rgba8Unorm, blend: None, write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState { cull_mode: Some(wgpu::Face::Back), ..Default::default() },
            depth_stencil: Some(wgpu::DepthStencilState {
                format: wgpu::TextureFormat::Depth24Plus, depth_write_enabled: Some(true),
                depth_compare: Some(wgpu::CompareFunction::LessEqual), stencil: Default::default(), bias: Default::default(),
            }),
            multisample: wgpu::MultisampleState { count: SAMPLES, ..Default::default() },
            multiview_mask: None, cache: None,
        });
        let composite_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("Blue armor gamma composite"),
            layout: Some(&composite_pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_composite"),
                buffers: &[],
                compilation_options: Default::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_composite"),
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format: wgpu::TextureFormat::Rgba8Unorm,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: Default::default(),
            depth_stencil: None,
            multisample: Default::default(),
            multiview_mask: None,
            cache: None,
        });
        let vertices = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Blue armor indexed vertices"),
            contents: bytemuck::cast_slice(&mesh.vertices),
            usage: wgpu::BufferUsages::VERTEX,
        });
        let indices = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("Blue armor triangle indices"),
            contents: bytemuck::cast_slice(&mesh.indices),
            usage: wgpu::BufferUsages::INDEX,
        });
        Self {
            scene_pipeline,
            composite_pipeline,
            vertices,
            indices,
            index_count: mesh.indices.len() as u32,
            uniform_buffer,
            scene_group,
            composite_group,
            scene_view,
            resolve_view,
            depth_view,
            output_view,
            previous: None,
        }
    }

    fn render(&self, encoder: &mut wgpu::CommandEncoder) {
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("Blue armor depth-tested scene"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &self.scene_view,
                    depth_slice: None,
                    resolve_target: Some(&self.resolve_view),
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::TRANSPARENT),
                        store: wgpu::StoreOp::Discard,
                    },
                })],
                depth_stencil_attachment: Some(wgpu::RenderPassDepthStencilAttachment {
                    view: &self.depth_view,
                    depth_ops: Some(wgpu::Operations {
                        load: wgpu::LoadOp::Clear(1.0),
                        store: wgpu::StoreOp::Discard,
                    }),
                    stencil_ops: None,
                }),
                ..Default::default()
            });
            pass.set_pipeline(&self.scene_pipeline);
            pass.set_bind_group(0, &self.scene_group, &[]);
            pass.set_vertex_buffer(0, self.vertices.slice(..));
            pass.set_index_buffer(self.indices.slice(..), wgpu::IndexFormat::Uint32);
            pass.draw_indexed(0..self.index_count, 0, 0..1);
        }
        let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
            label: Some("Blue armor cached egui image"),
            color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                view: &self.output_view,
                depth_slice: None,
                resolve_target: None,
                ops: wgpu::Operations {
                    load: wgpu::LoadOp::Clear(wgpu::Color::TRANSPARENT),
                    store: wgpu::StoreOp::Store,
                },
            })],
            ..Default::default()
        });
        pass.set_pipeline(&self.composite_pipeline);
        pass.set_bind_group(0, &self.composite_group, &[]);
        pass.draw(0..3, 0..1);
    }
}

fn target(
    device: &wgpu::Device,
    label: &str,
    format: wgpu::TextureFormat,
    samples: u32,
    sampled: bool,
) -> wgpu::TextureView {
    let usage = wgpu::TextureUsages::RENDER_ATTACHMENT
        | if sampled {
            wgpu::TextureUsages::TEXTURE_BINDING
        } else {
            wgpu::TextureUsages::empty()
        };
    // Texture views retain their parent textures, as all wgpu handles are refcounted.
    device
        .create_texture(&wgpu::TextureDescriptor {
            label: Some(label),
            size: wgpu::Extent3d {
                width: RESOLUTION,
                height: RESOLUTION,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: samples,
            dimension: wgpu::TextureDimension::D2,
            format,
            usage,
            view_formats: &[],
        })
        .create_view(&wgpu::TextureViewDescriptor::default())
}

fn validate_shader() -> Result<(), String> {
    let module =
        wgpu::naga::front::wgsl::parse_str(SHADER).map_err(|error| error.emit_to_string(SHADER))?;
    wgpu::naga::valid::Validator::new(
        wgpu::naga::valid::ValidationFlags::all(),
        wgpu::naga::valid::Capabilities::empty(),
    )
    .validate(&module)
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Unknown is deliberately not interpreted as enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum LayerState {
    Off = 0,
    On = 1,
    Limited = 2,
    #[default]
    Unknown = 3,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShieldState {
    pub files: LayerState,
    pub dns: LayerState,
    pub integrity: LayerState,
    pub scanning: bool,
}

/// Presentation-only layer identity. Inspection never changes protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ShieldLayer {
    Files = 0,
    Dns = 1,
    Integrity = 2,
}

impl ShieldLayer {
    const ALL: [Self; 3] = [Self::Files, Self::Dns, Self::Integrity];

    fn label(self) -> &'static str {
        match self {
            Self::Files => "Files",
            Self::Dns => "DNS",
            Self::Integrity => "Integrity",
        }
    }

    fn state(self, state: ShieldState) -> LayerState {
        match self {
            Self::Files => state.files,
            Self::Dns => state.dns,
            Self::Integrity => state.integrity,
        }
    }
}

fn adjacent_layer(inspected: Option<ShieldLayer>, direction: i32) -> ShieldLayer {
    let index = inspected.map_or(if direction < 0 { 0 } else { -1 }, |layer| layer as i32);
    ShieldLayer::ALL[(index + direction).rem_euclid(3) as usize]
}

impl LayerState {
    fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::On => "On",
            Self::Limited => "Limited",
            Self::Unknown => "Unknown",
        }
    }

    fn color(self) -> Color32 {
        match self {
            Self::On => Color32::from_rgb(102, 216, 176),
            Self::Limited => Color32::from_rgb(255, 169, 107),
            Self::Off => Color32::from_rgb(148, 163, 195),
            Self::Unknown => Color32::from_rgb(179, 188, 212),
        }
    }
}

/// Construct once from eframe's creation context, then retain between frames.
pub struct Shield {
    gpu: Option<GpuHandle>,
    fallback: Fallback,
    motion: Motion,
    inspected: Option<ShieldLayer>,
    previous_pick: Option<(Rect, [Mat4; 3], egui::Pos2, Option<ShieldLayer>)>,
}

impl Shield {
    /// Selects a visual inspection pose, not a protection setting.
    pub fn set_inspected_layer(&mut self, layer: Option<ShieldLayer>) {
        self.inspected = layer;
    }

    pub fn inspected_layer(&self) -> Option<ShieldLayer> {
        self.inspected
    }

    fn pick_layer(&mut self, rect: Rect, pointer: egui::Pos2) -> Option<ShieldLayer> {
        let models = self.motion.models();
        if let Some((previous_rect, previous_models, previous_pointer, layer)) = self.previous_pick
        {
            if rect == previous_rect && models == previous_models && pointer == previous_pointer {
                return layer;
            }
        }
        let layer = self.fallback.source.pick(rect, models, pointer);
        self.previous_pick = Some((rect, models, pointer, layer));
        layer
    }

    /// Returns an inspection response. Clicking never operates protection.
    pub fn paint(
        &mut self,
        ui: &mut egui::Ui,
        state: ShieldState,
        reduced_motion: bool,
    ) -> Response {
        let width = ui.available_width().clamp(1.0, 360.0);
        let static_mode = reduced_motion || self.gpu.is_none();
        let (rect, mut response) = ui.allocate_exact_size(
            egui::vec2(width, width * 0.84 + footer_height(width)),
            if static_mode {
                Sense::click()
            } else {
                Sense::click_and_drag()
            },
        );
        let (scene, labels) = shield_layout(rect);
        let before = self.inspected;
        let label_responses: [Response; 3] = std::array::from_fn(|index| {
            let layer = ShieldLayer::ALL[index];
            let label = ui.interact(
                labels[index],
                response.id.with(layer as u32),
                Sense::click(),
            );
            label.widget_info(|| {
                egui::WidgetInfo::labeled(
                    egui::Role::Button,
                    ui.is_enabled(),
                    format!(
                        "Inspect {}. Reported {}. Protection is unchanged.",
                        layer.label(),
                        layer.state(state).label()
                    ),
                )
            });
            label.on_hover_text(format!(
                "Inspect {} coverage. This does not enable or disable protection.",
                layer.label()
            ))
        });
        for (index, label) in label_responses.iter().enumerate() {
            if label.clicked() {
                let layer = ShieldLayer::ALL[index];
                self.inspected = Some(layer);
            }
        }
        if ui.is_enabled() && response.has_focus() {
            let (left, right, clear) = ui.input_mut(|input| {
                (
                    input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowLeft),
                    input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowRight),
                    input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
                        || input.consume_key(egui::Modifiers::NONE, egui::Key::Home),
                )
            });
            if left || right {
                self.inspected = Some(adjacent_layer(self.inspected, if left { -1 } else { 1 }));
            } else if clear {
                self.inspected = None;
            }
        } else if ui.is_enabled()
            && label_responses.iter().any(Response::has_focus)
            && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.inspected = None;
        }
        let (time, focused) = ui.input(|input| {
            (
                input.time,
                input.focused && !input.viewport().minimized.unwrap_or(false),
            )
        });
        let visible = ui.is_rect_visible(rect) && scene.height() > 1.0;
        let animate = visible
            && ui.is_rect_visible(scene)
            && focused
            && !reduced_motion
            && self.gpu.is_some()
            && ui.is_enabled();
        if static_mode {
            self.motion.rotation = Vec2::ZERO;
            self.motion.drag = Vec2::ZERO;
            self.motion.target = Vec2::ZERO;
            self.motion.snap_selection(self.inspected);
        }
        // Egui owns Enter/Space and accessibility activation. Pointer clicks
        // still inspect the visible, depth-tested layer rather than toggling.
        if response.clicked() {
            if ui.input(|input| input.pointer.primary_clicked()) {
                if let Some(pointer) = response
                    .interact_pointer_pos()
                    .filter(|p| scene.contains(*p))
                {
                    let layer = self.pick_layer(scene, pointer);
                    self.inspected = layer;
                    ui.ctx().request_repaint();
                }
            } else {
                self.inspected = if self.inspected.is_some() {
                    None
                } else {
                    Some(ShieldLayer::Files)
                };
            }
        }
        let drag = if response.dragged() && response.hover_pos().is_some_and(|p| scene.contains(p))
        {
            response.drag_motion() * 0.005
        } else {
            Vec2::ZERO
        };
        self.motion.update(
            time,
            animate,
            static_mode,
            state.scanning,
            self.inspected,
            drag,
        );
        let hovered = response
            .hover_pos()
            .filter(|p| scene.contains(*p))
            .and_then(|p| self.pick_layer(scene, p));
        if before != self.inspected {
            response.mark_changed();
            ui.ctx().request_repaint();
        }
        response.widget_info(|| {
            egui::WidgetInfo::labeled(
                egui::Role::Button,
                ui.is_enabled(),
                format!(
                    "Inspect protection. Files {}. DNS {}. Integrity {}. {}. Use left and right arrows to inspect; Escape clears inspection.{}",
                    state.files.label(),
                    state.dns.label(),
                    state.integrity.label(),
                    self.inspected.map_or("Assembled shield", ShieldLayer::label),
                    if state.scanning { " Scan in progress." } else { "" },
                ),
            )
        });
        if visible {
            let uniforms = Uniforms::new(scene, state, &self.motion, animate, hovered);
            if let Some(gpu) = &self.gpu {
                ui.painter().add(egui_wgpu::Callback::new_paint_callback(
                    scene,
                    ShieldCallback {
                        id: gpu.id,
                        uniforms,
                    },
                ));
                ui.painter().image(
                    gpu.texture,
                    scene,
                    Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                    Color32::WHITE,
                );
            } else {
                self.fallback.paint(ui, scene, uniforms);
            }
            paint_labels(ui, labels, &label_responses, state, self.inspected);
            if state.scanning {
                ui.painter().text(
                    scene.left_top() + egui::vec2(8.0, 6.0),
                    egui::Align2::LEFT_TOP,
                    "Scan in progress",
                    FontId::proportional(11.5),
                    PEARL,
                );
            }
            if response.has_focus() {
                ui.painter().rect_stroke(
                    scene.shrink(1.0),
                    8.0,
                    Stroke::new(1.5, PEARL),
                    egui::StrokeKind::Inside,
                );
            }
        }
        if animate && self.motion.needs_frame(state.scanning) {
            ui.ctx().request_repaint_after(Duration::from_millis(
                if self.motion.needs_pose_frame() {
                    16
                } else {
                    33
                },
            ));
        }
        if let Some(layer) = hovered {
            response
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(format!(
                    "{}: reported {}. Click to inspect coverage; protection is unchanged.",
                    layer.label(),
                    layer.state(state).label(),
                ))
        } else {
            response.on_hover_text(if static_mode {
                "Select a layer or its label to inspect reported coverage. Static pose; protection is unchanged."
            } else {
                "Select a layer or its label to inspect reported coverage; drag to examine the armor. Protection is unchanged."
            })
        }
    }

    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mesh = MeshData::new();
        let gpu = cc.wgpu_render_state.as_ref().and_then(|state| {
            validate_shader().ok()?;
            let resources = GpuResources::new(&state.device, &mesh);
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let mut renderer = state.renderer.write();
            let texture = renderer.register_native_texture(
                &state.device,
                &resources.output_view,
                wgpu::FilterMode::Linear,
            );
            if renderer.callback_resources.get::<ResourceStore>().is_none() {
                renderer.callback_resources.insert(ResourceStore::default());
            }
            renderer
                .callback_resources
                .get_mut::<ResourceStore>()?
                .0
                .insert(id, resources);
            Some(GpuHandle {
                id,
                texture,
                renderer: state.renderer.clone(),
            })
        });
        Self {
            gpu,
            fallback: Fallback::new(mesh),
            motion: Motion::default(),
            inspected: None,
            previous_pick: None,
        }
    }
}

#[derive(Default)]
struct Motion {
    last_time: Option<f64>,
    phase: f32,
    scanning: bool,
    rotation: Vec2,
    drag: Vec2,
    target: Vec2,
    layers: [f32; 3],
    velocities: [f32; 3],
    inspected: Option<ShieldLayer>,
}

impl Motion {
    fn elapsed(&mut self, now: f64, enabled: bool) -> f32 {
        let gap = self.last_time.map(|last| now - last).unwrap_or(0.0);
        self.last_time = Some(now);
        // A missing page or a stalled frame must not advance the animation clock.
        if enabled && gap.is_finite() && (0.0..=0.20).contains(&gap) {
            (gap as f32).min(0.05)
        } else {
            0.0
        }
    }

    fn snap_selection(&mut self, inspected: Option<ShieldLayer>) {
        self.inspected = inspected;
        self.layers = std::array::from_fn(|index| {
            if inspected == Some(ShieldLayer::ALL[index]) {
                1.0
            } else {
                0.0
            }
        });
        self.velocities = [0.0; 3];
    }

    fn models(&self) -> [Mat4; 3] {
        let model = rotation(REST_YAW + self.rotation.x, REST_PITCH + self.rotation.y);
        std::array::from_fn(|layer| {
            let offset = std::array::from_fn(|axis| {
                OFFSETS[layer][axis]
                    + (0..3)
                        .map(|selected| {
                            INSPECTION_OFFSETS[selected][layer][axis] * self.layers[selected]
                        })
                        .sum::<f32>()
            });
            let yaw = (0..3)
                .map(|selected| INSPECTION_YAWS[selected][layer] * self.layers[selected])
                .sum();
            multiply(model, multiply(translation(offset), rotation(yaw, 0.0)))
        })
    }

    fn update(
        &mut self,
        now: f64,
        enabled: bool,
        static_mode: bool,
        scanning: bool,
        inspected: Option<ShieldLayer>,
        drag: Vec2,
    ) {
        let dt = self.elapsed(now, enabled);
        if scanning != self.scanning {
            self.phase = 0.0;
        }
        self.scanning = scanning;
        self.inspected = inspected;
        if static_mode {
            self.rotation = Vec2::ZERO;
            self.drag = Vec2::ZERO;
            self.target = Vec2::ZERO;
            self.snap_selection(inspected);
            return;
        }
        if !enabled {
            return;
        }
        if scanning {
            self.phase = (self.phase + dt * 0.32).fract();
        }
        self.drag.x = (self.drag.x + drag.x).clamp(-0.35, 0.35);
        self.drag.y = (self.drag.y + drag.y).clamp(-0.18, 0.18);
        self.target = self.drag;
        self.rotation += (self.target - self.rotation) * (1.0 - (-20.0 * dt).exp());
        if (self.target - self.rotation).length_sq() < 0.000001 {
            self.rotation = self.target;
        }
        for index in 0..3 {
            let target = if inspected == Some(ShieldLayer::ALL[index]) {
                1.0
            } else {
                0.0
            };
            let displacement = self.layers[index] - target;
            let decay = (-22.0 * dt).exp();
            let impulse = (self.velocities[index] + 22.0 * displacement) * dt;
            self.layers[index] = (target + (displacement + impulse) * decay).clamp(0.0, 1.0);
            self.velocities[index] = (self.velocities[index] - 22.0 * impulse) * decay;
            if (target - self.layers[index]).abs() < 0.00015 && self.velocities[index].abs() < 0.003
            {
                self.layers[index] = target;
                self.velocities[index] = 0.0;
            }
        }
    }

    fn needs_pose_frame(&self) -> bool {
        (self.target - self.rotation).length_sq() >= 0.000001
            || (0..3).any(|index| {
                let target = if self.inspected == Some(ShieldLayer::ALL[index]) {
                    1.0
                } else {
                    0.0
                };
                (target - self.layers[index]).abs() >= 0.00015
                    || self.velocities[index].abs() >= 0.003
            })
    }

    fn needs_frame(&self, scanning: bool) -> bool {
        scanning || self.needs_pose_frame()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_wgsl_parses_and_validates_without_adapter() {
        validate_shader().expect("armor WGSL must validate with baseline capabilities");
    }

    #[test]
    fn layouts_match_shader_and_vertex_attributes() {
        assert_eq!(std::mem::size_of::<Uniforms>(), 304);
        assert_eq!(std::mem::offset_of!(Uniforms, view_projection), 192);
        assert_eq!(std::mem::offset_of!(Uniforms, camera_phase), 256);
        assert_eq!(std::mem::offset_of!(Uniforms, states), 272);
        assert_eq!(std::mem::offset_of!(Uniforms, inspection), 288);
        assert_eq!(std::mem::size_of::<Vertex>(), 44);
        assert_eq!(std::mem::offset_of!(Vertex, layer), 32);
        assert_eq!(std::mem::offset_of!(Vertex, surface), 36);
        let module = wgpu::naga::front::wgsl::parse_str(SHADER).unwrap();
        let (_, uniforms) = module
            .types
            .iter()
            .find(|(_, ty)| ty.name.as_deref() == Some("Uniforms"))
            .unwrap();
        let wgpu::naga::TypeInner::Struct { members, span } = &uniforms.inner else {
            panic!("WGSL uniforms must remain a struct");
        };
        assert_eq!(*span, 304);
        assert_eq!(
            members
                .iter()
                .map(|member| member.offset)
                .collect::<Vec<_>>(),
            [0, 192, 256, 272, 288]
        );
    }

    #[test]
    fn unknown_is_the_default_not_enabled() {
        let state = ShieldState::default();
        assert_eq!(
            [state.files, state.dns, state.integrity],
            [LayerState::Unknown; 3]
        );
        assert!(!state.scanning);
    }
    #[test]
    fn each_laminate_is_closed_non_degenerate_and_outward_wound() {
        let mesh = MeshData::new();
        let samples = CONTOUR.len() * CONTOUR_STEPS;
        let triangles_per_layer = samples * (4 * BEVEL_STEPS + 2 + 2 * FACE_RINGS);
        assert_eq!(mesh.indices.len(), triangles_per_layer * 3 * 3);
        let mut edges = HashMap::new();
        for layer in 0..3 {
            assert_eq!(
                mesh.indices
                    .as_chunks::<3>()
                    .0
                    .iter()
                    .filter(|triangle| mesh.vertices[triangle[0] as usize].layer == layer)
                    .count(),
                triangles_per_layer
            );
        }
        for triangle in mesh.indices.as_chunks::<3>().0 {
            let [a, b, c]: [Vertex; 3] =
                std::array::from_fn(|i| mesh.vertices[triangle[i] as usize]);
            let face = cross(sub(b.position, a.position), sub(c.position, a.position));
            assert!(dot(face, face) > 0.000000000001);
            for vertex in [a, b, c] {
                assert!(dot(face, vertex.normal) > 0.0);
                assert!((dot(vertex.normal, vertex.normal) - 1.0).abs() < 0.0001);
            }
            assert_eq!(a.layer, b.layer);
            assert_eq!(b.layer, c.layer);
            let layer = a.layer;
            let points = [a, b, c].map(|vertex| {
                vertex
                    .position
                    .map(|value| (value * 1_000_000.0).round() as i32)
            });
            for (a, b) in [
                (points[0], points[1]),
                (points[1], points[2]),
                (points[2], points[0]),
            ] {
                let (edge, direction) = if a < b {
                    ((a, b, layer), 1)
                } else {
                    ((b, a, layer), -1)
                };
                let entry = edges.entry(edge).or_insert((0, 0));
                entry.0 += 1;
                entry.1 += direction;
            }
        }
        assert!(
            edges.values().all(|&edge| edge == (2, 0)),
            "every geometric edge must have two opposing faces"
        );
    }

    #[test]
    fn bevels_have_continuous_normals_and_crowned_faces() {
        let mesh = MeshData::new();
        let outline = contour();
        for pair in outline.windows(2) {
            assert!(
                pair[0].outward[0] * pair[1].outward[0] + pair[0].outward[1] * pair[1].outward[1]
                    > 0.90
            );
        }
        let front = &mesh.vertices[0..1 + FACE_RINGS * outline.len()];
        assert!((front[0].position[2] - HALF_THICKNESS - CROWN).abs() < 0.000001);
        for vertex in &front[front.len() - outline.len()..] {
            assert_eq!(vertex.normal, [0.0, 0.0, 1.0]);
            assert!((vertex.position[2] - HALF_THICKNESS).abs() < 0.000001);
        }
    }

    fn projected(rect: Rect, model: Mat4, point: [f32; 3]) -> egui::Pos2 {
        let world = transform(model, [point[0], point[1], point[2], 1.0]);
        let clip = transform(view_projection(rect.width() / rect.height()), world);
        rect.center()
            + egui::vec2(
                clip[0] / clip[3] * rect.width() * 0.5,
                -clip[1] / clip[3] * rect.height() * 0.5,
            )
    }

    fn fallback_shield() -> Shield {
        Shield {
            gpu: None,
            fallback: Fallback::new(MeshData::new()),
            motion: Motion::default(),
            inspected: None,
            previous_pick: None,
        }
    }

    fn shield_frame(
        ctx: &egui::Context,
        shield: &mut Shield,
        time: f64,
        events: Vec<egui::Event>,
        reduced_motion: bool,
    ) -> Response {
        let mut response = None;
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 620.0),
            )),
            time: Some(time),
            focused: true,
            events,
            ..Default::default()
        };
        let _ = ctx.run_ui(input, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                response = Some(shield.paint(ui, ShieldState::default(), reduced_motion));
            });
        });
        response.expect("shield must produce an inspection response")
    }

    #[test]
    fn shield_keyboard_activation_uses_egui_click_once() {
        for key in [egui::Key::Enter, egui::Key::Space] {
            let ctx = egui::Context::default();
            let mut shield = fallback_shield();
            let response = shield_frame(&ctx, &mut shield, 0.0, Vec::new(), false);
            ctx.memory_mut(|memory| memory.request_focus(response.id));
            let key_event = |pressed| egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            };
            for (frame, expected) in [(1, Some(ShieldLayer::Files)), (3, None)] {
                let activation = shield_frame(
                    &ctx,
                    &mut shield,
                    f64::from(frame) / 60.0,
                    vec![key_event(true)],
                    false,
                );
                assert!(activation.clicked(), "{key:?} must activate the shield");
                assert!(activation.changed());
                assert_eq!(shield.inspected_layer(), expected);
                let release = shield_frame(
                    &ctx,
                    &mut shield,
                    f64::from(frame + 1) / 60.0,
                    vec![key_event(false)],
                    false,
                );
                assert!(!release.clicked());
                assert_eq!(shield.inspected_layer(), expected);
            }
        }
    }

    #[test]
    fn static_shield_sensing_is_click_only() {
        let ctx = egui::Context::default();
        let mut shield = fallback_shield();
        for (frame, reduced_motion) in [false, true].into_iter().enumerate() {
            let response = shield_frame(
                &ctx,
                &mut shield,
                frame as f64 / 60.0,
                Vec::new(),
                reduced_motion,
            );
            assert!(response.sense.senses_click());
            assert!(!response.sense.senses_drag());
        }
    }

    #[test]
    fn shield_pointer_activation_keeps_depth_picking() {
        let ctx = egui::Context::default();
        let mut shield = fallback_shield();
        shield.set_inspected_layer(Some(ShieldLayer::Dns));
        let response = shield_frame(&ctx, &mut shield, 0.0, Vec::new(), false);
        let (scene, _) = shield_layout(response.rect);
        let pointer = projected(
            scene,
            shield.motion.models()[ShieldLayer::Dns as usize],
            [0.0, 0.0, HALF_THICKNESS + CROWN],
        );
        let _ = shield_frame(
            &ctx,
            &mut shield,
            0.01,
            vec![egui::Event::PointerMoved(pointer)],
            false,
        );
        for (time, pressed) in [(0.02, true), (0.03, false)] {
            let response = shield_frame(
                &ctx,
                &mut shield,
                time,
                vec![egui::Event::PointerButton {
                    pos: pointer,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                }],
                false,
            );
            assert_eq!(response.clicked(), !pressed);
            assert_eq!(shield.inspected_layer(), Some(ShieldLayer::Dns));
        }
    }

    #[test]
    fn picking_matches_the_depth_tested_inspection_pose() {
        let mesh = MeshData::new();
        for size in [egui::vec2(360.0, 302.4), egui::vec2(160.0, 134.4)] {
            let rect = Rect::from_min_size(egui::pos2(27.0, 19.0), size);
            let mut motion = Motion::default();
            let point = projected(rect, motion.models()[0], [0.0, 0.0, HALF_THICKNESS + CROWN]);
            assert_eq!(
                mesh.pick(rect, motion.models(), point),
                Some(ShieldLayer::Files)
            );
            for layer in ShieldLayer::ALL {
                motion.snap_selection(Some(layer));
                let models = motion.models();
                let point = projected(
                    rect,
                    models[layer as usize],
                    [0.0, 0.0, HALF_THICKNESS + CROWN],
                );
                assert_eq!(mesh.pick(rect, models, point), Some(layer));
                assert_eq!(mesh.pick(rect, models, rect.left_top()), None);
                assert_eq!(
                    mesh.pick(rect, models, rect.right_bottom() + Vec2::splat(1.0)),
                    None
                );
            }
        }
    }

    #[test]
    fn picking_rejects_back_faces_and_misses() {
        let triangle = [[-1.0, -1.0, 0.0], [1.0, -1.0, 0.0], [0.0, 1.0, 0.0]];
        assert_eq!(
            ray_triangle([0.0, 0.0, 2.0], [0.0, 0.0, -1.0], triangle),
            Some(2.0)
        );
        assert_eq!(
            ray_triangle([0.0, 0.0, -2.0], [0.0, 0.0, 1.0], triangle),
            None
        );
        assert_eq!(
            ray_triangle([3.0, 0.0, 2.0], [0.0, 0.0, -1.0], triangle),
            None
        );
    }

    #[test]
    fn inspection_is_separate_from_reported_protection() {
        let mut shield = Shield {
            gpu: None,
            fallback: Fallback::new(MeshData::new()),
            motion: Motion::default(),
            inspected: None,
            previous_pick: None,
        };
        let state = ShieldState::default();
        let rect = Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(360.0, 302.4));
        for layer in ShieldLayer::ALL {
            shield.set_inspected_layer(Some(layer));
            assert_eq!(shield.inspected_layer(), Some(layer));
            shield.motion.snap_selection(shield.inspected_layer());
            let point = projected(
                rect,
                shield.motion.models()[layer as usize],
                [0.0, 0.0, HALF_THICKNESS + CROWN],
            );
            assert_eq!(shield.pick_layer(rect, point), Some(layer));
            assert_eq!(shield.pick_layer(rect, point), Some(layer));
            let uniforms = Uniforms::new(rect, state, &shield.motion, false, Some(layer));
            assert_eq!(
                uniforms.states,
                [
                    LayerState::Unknown as u32,
                    LayerState::Unknown as u32,
                    LayerState::Unknown as u32,
                    0
                ]
            );
        }
        shield.set_inspected_layer(None);
        assert_eq!(shield.inspected_layer(), None);
        assert_eq!(adjacent_layer(None, 1), ShieldLayer::Files);
        assert_eq!(adjacent_layer(None, -1), ShieldLayer::Integrity);
    }

    #[test]
    fn labels_remain_separate_accessible_targets_when_narrow() {
        for width in [150.0, 209.0, 210.0, 280.0, 360.0] {
            let rect = Rect::from_min_size(
                egui::pos2(11.0, 9.0),
                egui::vec2(width, width * 0.84 + footer_height(width)),
            );
            let (scene, labels) = shield_layout(rect);
            assert!(scene.height() > 0.0);
            for label in labels {
                assert!(rect.expand(0.001).contains_rect(label));
                assert!(label.height() >= 36.0);
                assert!(label.top() >= scene.bottom());
            }
            for pair in labels.windows(2) {
                assert!(
                    pair[0].right() <= pair[1].left() + 0.0001
                        || pair[0].bottom() <= pair[1].top() + 0.0001
                );
            }
        }
    }

    #[test]
    fn selection_motion_is_interruptible_and_settles_without_idle_motion() {
        let mut motion = Motion::default();
        let initial = motion.models();
        for frame in 0..60 {
            motion.update(frame as f64 / 60.0, true, false, false, None, Vec2::ZERO);
        }
        assert_eq!(motion.models(), initial);
        assert_eq!(motion.phase, 0.0);
        assert!(!motion.needs_frame(false));
        for frame in 60..66 {
            motion.update(
                frame as f64 / 60.0,
                true,
                false,
                false,
                Some(ShieldLayer::Files),
                Vec2::ZERO,
            );
        }
        assert!(motion.layers[0] > 0.0 && motion.layers[0] < 1.0);
        let interrupted = motion.models();
        motion.update(
            65.0 / 60.0,
            true,
            false,
            false,
            Some(ShieldLayer::Dns),
            Vec2::ZERO,
        );
        assert_eq!(motion.models(), interrupted);
        for frame in 66..150 {
            motion.update(
                frame as f64 / 60.0,
                true,
                false,
                false,
                Some(ShieldLayer::Dns),
                Vec2::ZERO,
            );
            assert!(motion
                .layers
                .iter()
                .all(|&value| (0.0..=1.0).contains(&value)));
        }
        assert_eq!(motion.layers, [0.0, 1.0, 0.0]);
        assert!(!motion.needs_frame(false));
    }

    #[test]
    fn hidden_motion_pauses_and_static_inspection_snaps_without_scanning() {
        let mut motion = Motion::default();
        motion.update(1.0, true, false, true, Some(ShieldLayer::Files), Vec2::ZERO);
        motion.update(
            1.02,
            true,
            false,
            true,
            Some(ShieldLayer::Files),
            Vec2::ZERO,
        );
        let pose = motion.models();
        let phase = motion.phase;
        motion.update(
            9.0,
            false,
            false,
            true,
            Some(ShieldLayer::Files),
            Vec2::ZERO,
        );
        assert_eq!(motion.models(), pose);
        assert_eq!(motion.phase, phase);
        motion.update(
            9.02,
            false,
            true,
            true,
            Some(ShieldLayer::Integrity),
            Vec2::splat(0.2),
        );
        assert_eq!(motion.rotation, Vec2::ZERO);
        assert_eq!(motion.layers, [0.0, 0.0, 1.0]);
        assert!(!motion.needs_pose_frame());
        let state = ShieldState {
            scanning: true,
            ..ShieldState::default()
        };
        let rect = Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(360.0, 302.4));
        assert_eq!(
            Uniforms::new(rect, state, &motion, false, None).states[3],
            0
        );
    }

    #[test]
    fn clock_does_not_catch_up_after_hidden_or_reduced_motion() {
        let mut motion = Motion::default();
        assert_eq!(motion.elapsed(1.0, true), 0.0);
        assert!(motion.elapsed(1.02, true) > 0.0);
        assert_eq!(motion.elapsed(20.0, true), 0.0);
        assert_eq!(motion.elapsed(20.02, false), 0.0);
        assert!(motion.elapsed(20.04, true) > 0.0);
        assert!(!motion.needs_frame(false));
        assert!(motion.needs_frame(true));
    }

    #[test]
    fn projection_uses_wgpu_depth_range() {
        let clip = transform(view_projection(1.0), [0.0, 0.0, 0.0, 1.0]);
        assert!(clip[3] > 0.0);
        assert!((0.0..1.0).contains(&(clip[2] / clip[3])));
    }
}
