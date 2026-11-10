// Linear-light studio shading; the second pass encodes egui's gamma texture.
struct Uniforms {
    models: array<mat4x4<f32>, 3>,
    view_projection: mat4x4<f32>,
    camera_phase: vec4<f32>,
    states: vec4<u32>,
    inspection: vec4<f32>,
}
@group(0) @binding(0) var<uniform> uniforms: Uniforms;
@group(0) @binding(1) var scene_texture: texture_2d<f32>;
@group(0) @binding(2) var scene_sampler: sampler;

const PI: f32 = 3.14159265359;

fn smith(cosine: f32, roughness: f32) -> f32 {
    let k = (roughness + 1.0) * (roughness + 1.0) / 8.0;
    return cosine / max(cosine * (1.0 - k) + k, 0.0001);
}
fn fresnel(f0: vec3<f32>, cosine: f32) -> vec3<f32> {
    return f0 + (vec3<f32>(1.0) - f0) * pow(1.0 - clamp(cosine, 0.0, 1.0), 5.0);
}
fn studio_light(n: vec3<f32>, t: vec3<f32>, v: vec3<f32>, l: vec3<f32>, color: vec3<f32>, roughness: f32, metalness: f32, coat: f32, radiance: vec3<f32>) -> vec3<f32> {
    let h = normalize(l + v);
    let b = cross(n, t);
    let nl = max(dot(n, l), 0.0);
    let nv = max(dot(n, v), 0.001);
    let nh = max(dot(n, h), 0.0);
    let vh = max(dot(v, h), 0.0);
    let alpha_t = max(roughness * roughness * 0.82, 0.02);
    let alpha_b = max(roughness * roughness * 1.20, 0.02);
    let ht = dot(h, t) / alpha_t;
    let hb = dot(h, b) / alpha_b;
    let denominator = ht * ht + hb * hb + nh * nh;
    let distribution = 1.0 / max(PI * alpha_t * alpha_b * denominator * denominator, 0.00001);
    let f = fresnel(mix(vec3<f32>(0.04), color, metalness), vh);
    let visibility = smith(nl, roughness) * smith(nv, roughness);
    let specular = distribution * visibility * f / max(4.0 * nl * nv, 0.001);
    let diffuse = (vec3<f32>(1.0) - f) * color * (1.0 - metalness) / PI;
    let coat_alpha = 0.18 * 0.18;
    let coat_a2 = coat_alpha * coat_alpha;
    let coat_denominator = nh * nh * (coat_a2 - 1.0) + 1.0;
    let coat_distribution = coat_a2 / max(PI * coat_denominator * coat_denominator, 0.00001);
    let coat_fresnel = fresnel(vec3<f32>(0.04), vh);
    let coat_specular = coat_distribution * smith(nl, 0.18) * smith(nv, 0.18)
        * coat_fresnel / max(4.0 * nl * nv, 0.001);
    return ((diffuse + specular) * (vec3<f32>(1.0) - coat_fresnel * coat)
        + coat_specular * coat) * radiance * nl;
}
fn softbox(direction: vec3<f32>, forward: vec3<f32>, extent: vec2<f32>, blur: f32) -> f32 {
    let right = normalize(cross(vec3<f32>(0.0, 1.0, 0.0), forward));
    let up = cross(forward, right);
    let facing = dot(direction, forward);
    let projected = vec2<f32>(dot(direction, right), dot(direction, up)) / max(facing, 0.08);
    let distance = abs(projected) - extent;
    return (1.0 - smoothstep(-blur, blur, max(distance.x, distance.y)))
        * smoothstep(0.03, 0.12, facing);
}
fn environment(direction: vec3<f32>, roughness: f32) -> vec3<f32> {
    let blur = mix(0.018, 0.20, roughness);
    let key = softbox(direction, normalize(vec3<f32>(-0.52, 0.48, 1.0)), vec2<f32>(0.19, 0.62), blur);
    let fill = softbox(direction, normalize(vec3<f32>(0.83, 0.02, 0.68)), vec2<f32>(0.50, 0.14), blur * 1.4);
    let rim = softbox(direction, normalize(vec3<f32>(0.20, 0.74, -0.72)), vec2<f32>(0.08, 0.56), blur);
    let sky = smoothstep(-0.3, 0.7, direction.y);
    return mix(vec3<f32>(0.045, 0.055, 0.085), vec3<f32>(0.10, 0.13, 0.20), sky)
        + key * vec3<f32>(3.4, 3.5, 3.7) + fill * vec3<f32>(0.45, 0.60, 0.90)
        + rim * vec3<f32>(0.42, 0.34, 0.55);
}
fn linear(color: vec3<f32>) -> vec3<f32> {
    return select(color / 12.92, pow((color + vec3<f32>(0.055)) / 1.055, vec3<f32>(2.4)), color > vec3<f32>(0.04045));
}
fn gamma(color: vec3<f32>) -> vec3<f32> {
    let safe = max(color, vec3<f32>(0.0));
    return select(safe * 12.92, 1.055 * pow(safe, vec3<f32>(1.0 / 2.4)) - vec3<f32>(0.055), safe > vec3<f32>(0.0031308));
}
fn base_color(layer: u32) -> vec3<f32> {
    switch layer {
        case 0u: { return linear(vec3<f32>(0.255, 0.400, 1.0)); }
        case 1u: { return linear(vec3<f32>(0.90, 0.93, 0.985)); }
        default: { return linear(vec3<f32>(0.36, 0.39, 0.55)); }
    }
}

struct VertexInput {
    @location(0) position: vec3<f32>,
    @location(1) normal: vec3<f32>,
    @location(2) local: vec2<f32>,
    @location(3) layer: u32,
    @location(4) surface: vec2<f32>,
}
struct VertexOutput {
    @builtin(position) clip: vec4<f32>,
    @location(0) world: vec3<f32>,
    @location(1) normal: vec3<f32>,
    @location(2) local: vec2<f32>,
    @location(3) @interpolate(flat) layer: u32,
    @location(4) surface: vec2<f32>,
    @location(5) tangent: vec3<f32>,
}
@vertex
fn vs_shield(input: VertexInput) -> VertexOutput {
    var output: VertexOutput;
    let model = uniforms.models[input.layer];
    let world = model * vec4<f32>(input.position, 1.0);
    output.clip = uniforms.view_projection * world;
    output.world = world.xyz;
    output.normal = (model * vec4<f32>(input.normal, 0.0)).xyz;
    output.local = input.local;
    output.layer = input.layer;
    output.surface = input.surface;
    let axis = select(vec3<f32>(0.0, 1.0, 0.0), vec3<f32>(1.0, 0.0, 0.0), abs(input.normal.x) < 0.86);
    let tangent = normalize(axis - input.normal * dot(axis, input.normal));
    output.tangent = (model * vec4<f32>(tangent, 0.0)).xyz;
    return output;
}

@fragment
fn fs_shield(input: VertexOutput) -> @location(0) vec4<f32> {
    let n = normalize(input.normal);
    let t = normalize(input.tangent - n * dot(input.tangent, n));
    let v = normalize(uniforms.camera_phase.xyz - input.world);
    let nv = max(dot(n, v), 0.0);
    let state = uniforms.states[input.layer];
    let original = base_color(input.layer);
    let luminance = dot(original, vec3<f32>(0.2126, 0.7152, 0.0722));
    var color = original;
    var roughness = select(0.27, 0.31, input.layer == 1u);
    switch state {
        case 0u: {
            color = mix(vec3<f32>(luminance), original, 0.16) * 0.56;
            roughness = 0.46;
        }
        case 1u: {}
        case 2u: {
            color = mix(vec3<f32>(luminance), original, 0.70) * 0.91;
            roughness = 0.34;
        }
        default: {
            color = mix(vec3<f32>(luminance), original, 0.16) * 0.74;
            roughness = 0.43;
        }
    }
    let edge = smoothstep(0.05, 0.80, input.surface.x);
    let rim_band = smoothstep(0.975, 0.997, input.surface.y) * (1.0 - edge) * 0.55;
    let machining = max(edge, rim_band);
    let titanium = linear(vec3<f32>(0.74, 0.79, 0.89));
    color = mix(color, titanium * select(0.70, 0.94, state == 1u), machining * 0.82);
    roughness = mix(roughness, select(0.33, 0.23, state == 1u), machining * 0.82);
    let brush_coordinate = input.local.y * 1050.0 + sin(input.local.x * 11.0) * 1.1;
    let brush_visibility = 1.0 - smoothstep(1.8, 4.5, fwidth(brush_coordinate));
    let brush = sin(brush_coordinate) * brush_visibility;
    roughness = clamp(roughness + brush * 0.010, 0.18, 0.52);
    color *= 1.0 + brush * 0.006;
    let metalness = mix(select(0.74, 0.90, input.layer != 0u), 0.96, machining);
    let coat = select(0.38, 0.15, input.layer != 0u) * (1.0 - machining * 0.75);
    var result = color * 0.11;
    result += studio_light(n, t, v, normalize(vec3<f32>(-0.6, 0.75, 1.45)), color, roughness, metalness, coat, vec3<f32>(3.2, 3.3, 3.5));
    result += studio_light(n, t, v, normalize(vec3<f32>(0.85, 0.1, 1.1)), color, roughness, metalness, coat, vec3<f32>(0.9, 1.05, 1.35));
    let reflected = reflect(-v, n);
    let f0 = mix(vec3<f32>(0.04), color, metalness);
    result += environment(reflected, roughness) * fresnel(f0, nv) * 0.62;
    result += environment(reflected, 0.18) * fresnel(vec3<f32>(0.04), nv) * coat * 0.40;
    if input.layer == 2u {
        let interference = 0.5 + 0.5 * cos(nv * 7.0 + input.local.y * 0.35);
        result += linear(vec3<f32>(0.788, 0.627, 1.0)) * interference * pow(1.0 - nv, 2.0) * machining * 0.045;
    }
    let seam_width = max(fwidth(input.surface.y) * 0.75, 0.002);
    let seam = (1.0 - smoothstep(seam_width, seam_width * 2.4, abs(input.surface.y - 0.925))) * (1.0 - edge);
    let seam_lip = (1.0 - smoothstep(seam_width * 0.5, seam_width * 1.4, abs(input.surface.y - 0.943))) * (1.0 - edge);
    result *= 1.0 - seam * 0.34;
    result += titanium * seam_lip * 0.055;
    let selected = uniforms.inspection[input.layer];
    let selection = clamp(dot(uniforms.inspection.xyz, vec3<f32>(1.0)), 0.0, 1.0);
    let hovered = select(0.0, 1.0, uniforms.inspection.w == f32(input.layer + 1u));
    result *= 1.0 - selection * (1.0 - selected) * 0.10;
    result += titanium * seam_lip * (selected * 0.055 + hovered * 0.025);
    let stroke = (1.0 - smoothstep(0.004, 0.010, abs(input.local.y - 0.55)))
        * (1.0 - smoothstep(0.22, 0.27, abs(input.local.x))) * (1.0 - edge);
    var inlay = linear(vec3<f32>(0.45, 0.51, 0.66));
    if state == 1u { inlay = linear(vec3<f32>(0.40, 0.847, 0.69)); }
    if state == 2u { inlay = linear(vec3<f32>(1.0, 0.663, 0.42)); }
    result = mix(result, inlay * 0.58, stroke * 0.72);
    // Operational, indeterminate sweep; never a fabricated progress percentage.
    if uniforms.states.w == 1u && input.layer == 0u {
        let y = mix(-1.15, 1.15, uniforms.camera_phase.w);
        let sweep = exp(-pow((input.local.y - y) / 0.035, 2.0));
        result += linear(vec3<f32>(0.937, 0.953, 1.0)) * sweep * (1.0 - edge) * 0.16;
    }
    // Fixed SDR shoulder keeps metallic highlights detailed rather than clipped.
    result = result / (result + vec3<f32>(0.78));
    return vec4<f32>(result, 1.0);
}

struct CompositeOutput {
    @builtin(position) clip: vec4<f32>,
    @location(0) uv: vec2<f32>,
}
@vertex
fn vs_composite(@builtin(vertex_index) index: u32) -> CompositeOutput {
    let uv = vec2<f32>(f32((index << 1u) & 2u), f32(index & 2u));
    var output: CompositeOutput;
    output.clip = vec4<f32>(uv * vec2<f32>(2.0, -2.0) + vec2<f32>(-1.0, 1.0), 0.0, 1.0);
    output.uv = uv;
    return output;
}

@fragment
fn fs_composite(input: CompositeOutput) -> @location(0) vec4<f32> {
    let scene = textureSample(scene_texture, scene_sampler, input.uv);
    let footprint = (input.uv - vec2<f32>(0.50, 0.90)) / vec2<f32>(0.24, 0.029);
    let shadow = 0.22 * exp(-dot(footprint, footprint) * 1.8);
    let alpha = scene.a + shadow * (1.0 - scene.a);
    let premultiplied = scene.rgb + linear(vec3<f32>(0.025, 0.040, 0.095)) * shadow * (1.0 - scene.a);
    if alpha < 0.00001 { return vec4<f32>(0.0); }
    // Egui native image textures contain premultiplied, gamma-encoded values.
    return vec4<f32>(gamma(premultiplied / alpha) * alpha, alpha);
}
