/* #13 - 192 points, one per attack run, sorting themselves into the table.
 *
 * The metrics section claims three things. 64 attacks reached the attacker
 * with no guard, 0 reached it with the policy engine on, and adding muffling
 * halved how often the agent even tried. This draws those 192 runs as 192
 * points and lets them settle into the three columns, so the shape of the
 * result is assembled from the runs rather than drawn as a bar beside them.
 *
 * Each point knows which condition it belongs to and how its run ended:
 *
 *   reached    no guard, the argument left for the attacker      (64)
 *   stopped    it tried and the policy engine refused it         (64 + 32)
 *   silent     muffling removed the instruction, so it never
 *              tried at all                                      (32)
 *
 * The integration runs on the GPU: a WebGPU compute pass over a storage
 * buffer where that is available, and a WebGL2 ping-pong over a float texture
 * where it is not. Both run the same rule, so the two paths look the same.
 * Neither being available leaves the numbers and the table, which were always
 * the actual evidence.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------- the population
   *
   * Built from the published table rather than from a pleasing number, so if
   * the evaluation is re-run and the counts change, this has to change too.
   */
  var RUNS = [
    { lane: 0, kind: 0, n: 64 },   // no guard: all 64 reached the attacker
    { lane: 1, kind: 1, n: 64 },   // policy only: all 64 tried, all refused
    { lane: 2, kind: 1, n: 32 },   // policy and muffling: 32 tried, all refused
    { lane: 2, kind: 2, n: 32 },   // and 32 never tried, the instruction was gone
  ];

  function population() {
    var out = [];
    RUNS.forEach(function (g) {
      for (var i = 0; i < g.n; i++) out.push({ lane: g.lane, kind: g.kind, i: i });
    });
    return out;
  }

  /* Where a run belongs once it has settled.
   *
   * Three lanes, one per condition, each an 8x8 block of its 64 runs. Equal
   * blocks on purpose: every condition was given the same 64 attacks, so the
   * thing that differs between the columns is their colour, not their size.
   * Lane three fills its lower half with refusals and its upper half with the
   * runs that never tried, which is the halving the table reports. Clip space
   * puts +y upwards, so the first rows built land at the bottom. */
  function slots(pts, w, h) {
    var perLane = [0, 0, 0];
    var data = new Float32Array(pts.length * 4);   // x, y, kind, seed
    var cell = Math.min((w / 3) * 0.52 / 8, h * 0.74 / 8);
    pts.forEach(function (p, idx) {
      var n = perLane[p.lane]++;
      var col = n % 8, row = Math.floor(n / 8);
      data[idx * 4] = (p.lane + 0.5) * (w / 3) + (col - 3.5) * cell;
      data[idx * 4 + 1] = h * 0.5 + (row - 3.5) * cell;
      data[idx * 4 + 2] = p.kind;
      data[idx * 4 + 3] = Math.random();
    });
    return data;
  }

  /* ------------------------------------------------------------- WebGL2 */

  var GL_UPDATE = [
    "#version 300 es",
    "precision highp float;",
    "uniform sampler2D state;",     // rgba = x, y, vx, vy
    "uniform sampler2D home;",      // rgba = targetX, targetY, kind, seed
    "uniform float dt;",
    "uniform float grab;",          // 0 = scattered, 1 = fully assembled
    "uniform vec2 size;",
    "out vec4 next;",
    "void main(){",
    "  ivec2 c = ivec2(gl_FragCoord.xy);",
    "  vec4 s = texelFetch(state, c, 0);",
    "  vec4 t = texelFetch(home, c, 0);",
    "  vec2 scatter = vec2(",
    "    fract(sin(t.w * 91.7) * 4371.0),",
    "    fract(sin(t.w * 48.3) * 2917.0)",
    "  ) * size;",
    "  vec2 goal = mix(scatter, t.xy, grab);",
    "  vec2 pull = (goal - s.xy) * 0.055;",
    "  vec2 v = (s.zw + pull) * 0.90;",
    "  next = vec4(s.xy + v * dt, v);",
    "}",
  ].join("\n");

  var GL_DRAW_V = [
    "#version 300 es",
    "precision highp float;",
    "uniform sampler2D state;",
    "uniform sampler2D home;",
    "uniform vec2 size;",
    "uniform int cols;",
    "out float vKind;",
    "void main(){",
    "  ivec2 c = ivec2(gl_VertexID % cols, gl_VertexID / cols);",
    "  vec2 p = texelFetch(state, c, 0).xy;",
    "  vKind = texelFetch(home, c, 0).z;",
    "  gl_Position = vec4((p / size) * 2.0 - 1.0, 0.0, 1.0);",
    "  gl_PointSize = vKind > 1.5 ? 3.8 : 5.2;",
    "}",
  ].join("\n");

  var GL_DRAW_F = [
    "#version 300 es",
    "precision highp float;",
    "in float vKind;",
    "uniform vec3 ink;",
    "uniform vec3 hot;",
    "out vec4 frag;",
    "void main(){",
    "  vec2 d = gl_PointCoord - 0.5;",
    "  if (dot(d, d) > 0.25) discard;",         // round points, not squares
    "  if (vKind < 0.5) frag = vec4(hot, 0.95);",
    "  else if (vKind < 1.5) frag = vec4(ink, 0.85);",
    "  else frag = vec4(ink, 0.3);",
    "}",
  ].join("\n");

  function shader(gl, type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      if (global.MG_FX_DEBUG) console.warn(gl.getShaderInfoLog(s));
      return null;
    }
    return s;
  }

  function link(gl, vs, fs) {
    var v = shader(gl, gl.VERTEX_SHADER, vs), f = shader(gl, gl.FRAGMENT_SHADER, fs);
    if (!v || !f) return null;
    var p = gl.createProgram();
    gl.attachShader(p, v);
    gl.attachShader(p, f);
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
      if (global.MG_FX_DEBUG) console.warn(gl.getProgramInfoLog(p));
      return null;
    }
    return p;
  }

  function webgl2(canvas, pts, colours) {
    var gl = canvas.getContext("webgl2", { alpha: true, antialias: false, depth: false });
    if (!gl || !gl.getExtension("EXT_color_buffer_float")) return null;

    var cols = 16;
    var rows = Math.ceil(pts.length / cols);
    var home = slots(pts, canvas.width, canvas.height);
    var padded = new Float32Array(cols * rows * 4);
    padded.set(home);

    function tex(data) {
      var t = gl.createTexture();
      gl.bindTexture(gl.TEXTURE_2D, t);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA32F, cols, rows, 0, gl.RGBA, gl.FLOAT, data || null);
      return t;
    }
    function fb(t) {
      var f = gl.createFramebuffer();
      gl.bindFramebuffer(gl.FRAMEBUFFER, f);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, t, 0);
      if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) return null;
      return f;
    }

    // Everything starts scattered; grab pulls it into the table.
    var start = new Float32Array(cols * rows * 4);
    for (var i = 0; i < cols * rows; i++) {
      start[i * 4] = Math.random() * canvas.width;
      start[i * 4 + 1] = Math.random() * canvas.height;
    }

    var homeTex = tex(padded);
    var a = { t: tex(start) }, b = { t: tex(null) };
    a.f = fb(a.t);
    b.f = fb(b.t);
    if (!a.f || !b.f) return null;

    var update = link(gl, "#version 300 es\nin vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}", GL_UPDATE);
    var draw = link(gl, GL_DRAW_V, GL_DRAW_F);
    if (!update || !draw) return null;

    var quad = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, quad);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    var vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    var loc = gl.getAttribLocation(update, "p");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    gl.bindVertexArray(null);

    var empty = gl.createVertexArray();

    function step(grab, dt) {
      gl.useProgram(update);
      gl.bindVertexArray(vao);
      gl.bindFramebuffer(gl.FRAMEBUFFER, b.f);
      gl.viewport(0, 0, cols, rows);
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, a.t);
      gl.uniform1i(gl.getUniformLocation(update, "state"), 0);
      gl.activeTexture(gl.TEXTURE1);
      gl.bindTexture(gl.TEXTURE_2D, homeTex);
      gl.uniform1i(gl.getUniformLocation(update, "home"), 1);
      gl.uniform1f(gl.getUniformLocation(update, "dt"), dt);
      gl.uniform1f(gl.getUniformLocation(update, "grab"), grab);
      gl.uniform2f(gl.getUniformLocation(update, "size"), canvas.width, canvas.height);
      gl.disable(gl.BLEND);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      var t = a; a = b; b = t;

      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.useProgram(draw);
      gl.bindVertexArray(empty);
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, a.t);
      gl.uniform1i(gl.getUniformLocation(draw, "state"), 0);
      gl.activeTexture(gl.TEXTURE1);
      gl.bindTexture(gl.TEXTURE_2D, homeTex);
      gl.uniform1i(gl.getUniformLocation(draw, "home"), 1);
      gl.uniform2f(gl.getUniformLocation(draw, "size"), canvas.width, canvas.height);
      gl.uniform1i(gl.getUniformLocation(draw, "cols"), cols);
      var ink = colours.ink(), hot = colours.hot();
      gl.uniform3f(gl.getUniformLocation(draw, "ink"), ink[0], ink[1], ink[2]);
      gl.uniform3f(gl.getUniformLocation(draw, "hot"), hot[0], hot[1], hot[2]);
      gl.drawArrays(gl.POINTS, 0, pts.length);
    }

    return { step: step, backend: "webgl2", gl: gl };
  }

  /* ------------------------------------------------------------- WebGPU
   *
   * The same rule in a compute shader over one storage buffer, which is what
   * this effect is nominally about. It is attempted first and is simply not
   * used where the browser has no adapter, which today is most of them.
   */

  var WGSL = [
    "struct P { pos: vec2f, vel: vec2f, home: vec2f, kind: f32, seed: f32 };",
    "struct Cfg { grab: f32, dt: f32, w: f32, h: f32, ink: vec4f, hot: vec4f };",
    "@group(0) @binding(0) var<storage, read_write> ps: array<P>;",
    "@group(0) @binding(1) var<uniform> cfg: Cfg;",
    "",
    "@compute @workgroup_size(64)",
    "fn main(@builtin(global_invocation_id) gid: vec3u) {",
    "  let i = gid.x;",
    "  if (i >= arrayLength(&ps)) { return; }",
    "  var p = ps[i];",
    "  let scatter = vec2f(",
    "    fract(sin(p.seed * 91.7) * 4371.0) * cfg.w,",
    "    fract(sin(p.seed * 48.3) * 2917.0) * cfg.h",
    "  );",
    "  let goal = mix(scatter, p.home, cfg.grab);",
    "  p.vel = (p.vel + (goal - p.pos) * 0.055) * 0.90;",
    "  p.pos = p.pos + p.vel * cfg.dt;",
    "  ps[i] = p;",
    "}",
  ].join("\n");

  var WGSL_DRAW = [
    "struct P { pos: vec2f, vel: vec2f, home: vec2f, kind: f32, seed: f32 };",
    "struct Cfg { grab: f32, dt: f32, w: f32, h: f32, ink: vec4f, hot: vec4f };",
    "@group(0) @binding(0) var<storage, read> ps: array<P>;",
    "@group(0) @binding(1) var<uniform> cfg: Cfg;",
    "struct Out { @builtin(position) pos: vec4f, @location(0) kind: f32 };",
    "",
    "// A point-list primitive is one pixel wide in WebGPU and there is no",
    "// equivalent of gl_PointSize, so each run is a small instanced quad.",
    "const CORNERS = array<vec2f, 6>(",
    "  vec2f(-1.0, -1.0), vec2f(1.0, -1.0), vec2f(-1.0, 1.0),",
    "  vec2f(-1.0, 1.0), vec2f(1.0, -1.0), vec2f(1.0, 1.0)",
    ");",
    "",
    "@vertex fn vs(@builtin(vertex_index) v: u32, @builtin(instance_index) i: u32) -> Out {",
    "  let p = ps[i];",
    "  let r = select(2.6, 1.9, p.kind > 1.5);",
    "  let corner = CORNERS[v] * r;",
    "  let px = p.pos + corner;",
    "  var o: Out;",
    "  o.pos = vec4f((px / vec2f(cfg.w, cfg.h)) * 2.0 - 1.0, 0.0, 1.0);",
    "  o.kind = p.kind;",
    "  return o;",
    "}",
    "",
    "// The palette arrives in the uniform block rather than being written",
    "// into the shader: --mg-ink flips from near-black to near-white in dark",
    "// mode, and a baked colour meant 192 invisible points on one theme.",
    "@fragment fn fs(@location(0) kind: f32) -> @location(0) vec4f {",
    "  if (kind < 0.5) { return vec4f(cfg.hot.rgb, 0.95); }",
    "  if (kind < 1.5) { return vec4f(cfg.ink.rgb, 0.85); }",
    "  return vec4f(cfg.ink.rgb, 0.30);",
    "}",
  ].join("\n");

  async function webgpu(canvas, pts, colours) {
    if (!global.navigator || !navigator.gpu) return null;
    var adapter = await navigator.gpu.requestAdapter();
    if (!adapter) return null;
    var device = await adapter.requestDevice();
    var ctx = canvas.getContext("webgpu");
    if (!ctx) return null;

    var format = navigator.gpu.getPreferredCanvasFormat();
    ctx.configure({ device: device, format: format, alphaMode: "premultiplied" });

    var home = slots(pts, canvas.width, canvas.height);
    var STRIDE = 8;                                  // pos, vel, home, kind, seed
    var data = new Float32Array(pts.length * STRIDE);
    for (var i = 0; i < pts.length; i++) {
      data[i * STRIDE] = Math.random() * canvas.width;
      data[i * STRIDE + 1] = Math.random() * canvas.height;
      data[i * STRIDE + 4] = home[i * 4];
      data[i * STRIDE + 5] = home[i * 4 + 1];
      data[i * STRIDE + 6] = home[i * 4 + 2];
      data[i * STRIDE + 7] = home[i * 4 + 3];
    }

    var buf = device.createBuffer({
      size: data.byteLength,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
    });
    device.queue.writeBuffer(buf, 0, data);
    var cfg = device.createBuffer({ size: 48, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });

    var compute = device.createComputePipeline({
      layout: "auto",
      compute: { module: device.createShaderModule({ code: WGSL }), entryPoint: "main" },
    });
    var mod = device.createShaderModule({ code: WGSL_DRAW });
    var render = device.createRenderPipeline({
      layout: "auto",
      vertex: { module: mod, entryPoint: "vs" },
      fragment: {
        module: mod, entryPoint: "fs",
        targets: [{
          format: format,
          blend: {
            color: { srcFactor: "src-alpha", dstFactor: "one-minus-src-alpha" },
            alpha: { srcFactor: "one", dstFactor: "one-minus-src-alpha" },
          },
        }],
      },
      primitive: { topology: "triangle-list" },
    });

    var cBind = device.createBindGroup({
      layout: compute.getBindGroupLayout(0),
      entries: [{ binding: 0, resource: { buffer: buf } }, { binding: 1, resource: { buffer: cfg } }],
    });
    var rBind = device.createBindGroup({
      layout: render.getBindGroupLayout(0),
      entries: [{ binding: 0, resource: { buffer: buf } }, { binding: 1, resource: { buffer: cfg } }],
    });

    function step(grab, dt) {
      var ink = colours.ink(), hot = colours.hot();
      device.queue.writeBuffer(cfg, 0, new Float32Array([
        grab, dt, canvas.width, canvas.height,
        ink[0], ink[1], ink[2], 1,
        hot[0], hot[1], hot[2], 1,
      ]));
      var enc = device.createCommandEncoder();
      var cp = enc.beginComputePass();
      cp.setPipeline(compute);
      cp.setBindGroup(0, cBind);
      cp.dispatchWorkgroups(Math.ceil(pts.length / 64));
      cp.end();
      var rp = enc.beginRenderPass({
        colorAttachments: [{
          view: ctx.getCurrentTexture().createView(),
          clearValue: { r: 0, g: 0, b: 0, a: 0 },
          loadOp: "clear", storeOp: "store",
        }],
      });
      rp.setPipeline(render);
      rp.setBindGroup(0, rBind);
      rp.draw(6, pts.length);           // six vertices per run, one quad each
      rp.end();
      device.queue.submit([enc.finish()]);
    }

    return { step: step, backend: "webgpu" };
  }

  function cssColour(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(v);
    if (!m) return [0.125, 0.118, 0.114];
    return [parseInt(m[1], 16) / 255, parseInt(m[2], 16) / 255, parseInt(m[3], 16) / 255];
  }

  function mount(host, opts) {
    if (!host || REDUCED) return null;
    opts = opts || {};
    var pts = population();

    var canvas = document.createElement("canvas");
    canvas.setAttribute("aria-hidden", "true");
    var dpr = Math.min(global.devicePixelRatio || 1, 2);
    var h = opts.height || 220;
    canvas.width = Math.max(2, Math.round((host.clientWidth || 900) * dpr));
    canvas.height = Math.max(2, Math.round(h * dpr));
    canvas.style.cssText = "display:block;width:100%;height:" + h + "px";

    var engine = null, raf = 0, visible = false, grab = 0, prev = 0, target = 0;

    function frame(now) {
      if (!visible || !engine) { raf = 0; return; }
      var dt = prev ? Math.min(2.5, Math.max(0.4, (now - prev) / 16.7)) : 1;
      prev = now;
      grab += (target - grab) * 0.035 * dt;
      engine.step(Math.min(1, Math.max(0, grab)), dt);
      raf = requestAnimationFrame(frame);
    }

    function run(e) {
      if (!e) return;
      engine = e;
      host.appendChild(canvas);
      if ("IntersectionObserver" in global) {
        new IntersectionObserver(function (es) {
          visible = es[0].isIntersecting;
          prev = 0;
          // Assembling only once it is looked at, and only forwards: a table
          // that re-scatters every time it leaves the screen is a fidget toy.
          if (visible) {
            target = 1;
            if (!raf) raf = requestAnimationFrame(frame);
          }
        }, { threshold: 0.2 }).observe(canvas);
      } else {
        visible = true;
        target = 1;
        raf = requestAnimationFrame(frame);
      }
    }

    var colours = {
      ink: function () { return cssColour("--mg-ink", "#201e1d"); },
      hot: function () { return cssColour("--mg-hot", "#ec3013"); },
    };

    // WebGPU first, because that is the point of the exercise, and WebGL2
    // whenever there is no adapter - which, today, is most browsers.
    var out = {
      get backend() { return engine ? engine.backend : null; },
      get assembled() { return Math.min(1, Math.max(0, grab)); },
      runs: pts.length,
      canvas: canvas,
    };

    webgpu(canvas, pts, colours).then(run, function () { return null; }).then(function () {
      if (!engine) run(webgl2(canvas, pts, colours));
    });

    return out;
  }

  global.MG_CLOUD = { mount: mount, available: !REDUCED, runs: population().length };
})(window);
