/* #8 - the hero's fluid, and the one parameter it shares with the muffle.
 *
 * A Stam solver, run on the GPU in the usual five passes:
 *
 *   advect velocity   semi-Lagrangian, velocity carried along itself
 *   divergence        how much each cell is gaining or losing
 *   pressure          Jacobi, iterated, until the field is close to solenoidal
 *   project           subtract the pressure gradient, leaving it divergence-free
 *   advect dye        the visible part, carried by the finished velocity field
 *
 * It is here because of what it is wired to rather than because it moves. The
 * muffle's cutoff already drives two things: the Gaussian width that rounds
 * off the injected sentence, and a lowpass on the audio tone. It drives a
 * third here - dissipation. As the cutoff falls the fluid loses its momentum,
 * so the same sweep that blurs the sentence and dulls the note also takes the
 * motion out of the background. One parameter, three media.
 *
 * Everything is optional. No WebGL, no float textures, or reduced motion, and
 * the hero is exactly the hero it was without this file.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var VERT =
    "attribute vec2 p;varying vec2 uv;" +
    "void main(){uv=p*0.5+0.5;gl_Position=vec4(p,0.0,1.0);}";

  /* Shared prelude: every pass samples its neighbours the same way. */
  var HEAD = [
    "precision highp float;",
    "varying vec2 uv;",
    "uniform vec2 texel;",
  ].join("\n");

  var ADVECT = HEAD + [
    "uniform sampler2D src;",     // what is being carried
    "uniform sampler2D vel;",
    "uniform float dt;",
    "uniform float keep;",        // 1 = nothing is lost, < 1 = it decays
    "void main(){",
    "  vec2 back = uv - dt * texture2D(vel, uv).xy * texel;",
    "  gl_FragColor = keep * texture2D(src, back);",
    "}",
  ].join("\n");

  var DIVERGENCE = HEAD + [
    "uniform sampler2D vel;",
    "void main(){",
    "  float l = texture2D(vel, uv - vec2(texel.x, 0.0)).x;",
    "  float r = texture2D(vel, uv + vec2(texel.x, 0.0)).x;",
    "  float b = texture2D(vel, uv - vec2(0.0, texel.y)).y;",
    "  float t = texture2D(vel, uv + vec2(0.0, texel.y)).y;",
    "  gl_FragColor = vec4(0.5 * (r - l + t - b), 0.0, 0.0, 1.0);",
    "}",
  ].join("\n");

  /* One Jacobi sweep. Called repeatedly; each call brings the pressure field
   * closer to the one that makes the velocity divergence-free. */
  var PRESSURE = HEAD + [
    "uniform sampler2D pres;",
    "uniform sampler2D div;",
    "void main(){",
    "  float l = texture2D(pres, uv - vec2(texel.x, 0.0)).x;",
    "  float r = texture2D(pres, uv + vec2(texel.x, 0.0)).x;",
    "  float b = texture2D(pres, uv - vec2(0.0, texel.y)).x;",
    "  float t = texture2D(pres, uv + vec2(0.0, texel.y)).x;",
    "  float d = texture2D(div, uv).x;",
    "  gl_FragColor = vec4((l + r + b + t - d) * 0.25, 0.0, 0.0, 1.0);",
    "}",
  ].join("\n");

  var PROJECT = HEAD + [
    "uniform sampler2D pres;",
    "uniform sampler2D vel;",
    "void main(){",
    "  float l = texture2D(pres, uv - vec2(texel.x, 0.0)).x;",
    "  float r = texture2D(pres, uv + vec2(texel.x, 0.0)).x;",
    "  float b = texture2D(pres, uv - vec2(0.0, texel.y)).x;",
    "  float t = texture2D(pres, uv + vec2(0.0, texel.y)).x;",
    "  vec2 v = texture2D(vel, uv).xy - vec2(r - l, t - b);",
    "  gl_FragColor = vec4(v, 0.0, 1.0);",
    "}",
  ].join("\n");

  /* A soft round splat, added to whatever is already there. */
  var SPLAT = HEAD + [
    "uniform sampler2D src;",
    "uniform vec2 at;",
    "uniform vec3 amount;",
    "uniform float radius;",
    "uniform float aspect;",
    "void main(){",
    "  vec2 d = uv - at;",
    "  d.x *= aspect;",
    "  float fall = exp(-dot(d, d) / radius);",
    "  gl_FragColor = texture2D(src, uv) + vec4(fall * amount, 0.0);",
    "}",
  ].join("\n");

  /* The only pass anyone sees. The dye is one channel, mapped between the
   * page's own two inks, so the fluid cannot drift away from the palette. */
  var SHOW = HEAD + [
    "uniform sampler2D dye;",
    "uniform vec3 cold;",
    "uniform vec3 warm;",
    "void main(){",
    "  float d = clamp(texture2D(dye, uv).x, 0.0, 1.0);",
    "  float a = smoothstep(0.015, 0.5, d) * 0.30;",
    "  gl_FragColor = vec4(mix(cold, warm, smoothstep(0.1, 0.9, d)), a);",
    "}",
  ].join("\n");

  function compile(gl, type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      if (global.MG_FX_DEBUG) console.warn(gl.getShaderInfoLog(s), src);
      return null;
    }
    return s;
  }

  function program(gl, frag) {
    var vs = compile(gl, gl.VERTEX_SHADER, VERT);
    var fs = compile(gl, gl.FRAGMENT_SHADER, frag);
    if (!vs || !fs) return null;
    var p = gl.createProgram();
    gl.attachShader(p, vs);
    gl.attachShader(p, fs);
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) return null;
    p.u = {};
    var n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
    for (var i = 0; i < n; i++) {
      var name = gl.getActiveUniform(p, i).name;
      p.u[name] = gl.getUniformLocation(p, name);
    }
    return p;
  }

  function target(gl, w, h, type, fmt) {
    var tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texImage2D(gl.TEXTURE_2D, 0, fmt, w, h, 0, fmt, type, null);

    var fbo = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
    if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) return null;
    gl.clear(gl.COLOR_BUFFER_BIT);
    return { tex: tex, fbo: fbo, w: w, h: h };
  }

  /* Two targets and a swap: advection reads the previous state and writes the
   * next, which cannot be the same texture. */
  function pair(gl, w, h, type, fmt) {
    var a = target(gl, w, h, type, fmt);
    var b = target(gl, w, h, type, fmt);
    if (!a || !b) return null;
    return {
      read: a, write: b,
      swap: function () { var t = this.read; this.read = this.write; this.write = t; },
    };
  }

  function rgbToVec(css) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(css.trim());
    if (!m) return [0.13, 0.12, 0.11];
    return [parseInt(m[1], 16) / 255, parseInt(m[2], 16) / 255, parseInt(m[3], 16) / 255];
  }

  function mount(host, opts) {
    if (!host || REDUCED) return null;
    opts = opts || {};

    var canvas = document.createElement("canvas");
    canvas.setAttribute("aria-hidden", "true");
    canvas.style.cssText =
      "position:absolute;inset:0;width:100%;height:100%;display:block;pointer-events:none;z-index:0";
    var gl = canvas.getContext("webgl", { alpha: true, premultipliedAlpha: false, depth: false, antialias: false }) ||
             canvas.getContext("experimental-webgl", { alpha: true, depth: false });
    if (!gl) return null;

    // The simulation needs somewhere with range to store velocity. Half float
    // is enough and is far more widely available than full float; without
    // either there is no simulation to run, so the hero simply does without.
    var half = gl.getExtension("OES_texture_half_float");
    var type = null;
    if (gl.getExtension("OES_texture_float") && gl.getExtension("OES_texture_float_linear")) {
      type = gl.FLOAT;
    } else if (half && gl.getExtension("OES_texture_half_float_linear")) {
      type = half.HALF_FLOAT_OES;
    }
    if (type === null) return null;

    var progs = {
      advect: program(gl, ADVECT),
      diverge: program(gl, DIVERGENCE),
      pressure: program(gl, PRESSURE),
      project: program(gl, PROJECT),
      splat: program(gl, SPLAT),
      show: program(gl, SHOW),
    };
    for (var k in progs) if (!progs[k]) return null;

    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);

    // The grid is deliberately coarse. A hero background that costs a third of
    // the frame budget is a worse hero than a slightly soft one.
    var SIM = opts.sim || 128;
    var DYE = opts.dye || 256;

    var vel = pair(gl, SIM, SIM, type, gl.RGBA);
    var dye = pair(gl, DYE, DYE, type, gl.RGBA);
    var pres = pair(gl, SIM, SIM, type, gl.RGBA);
    var div = target(gl, SIM, SIM, type, gl.RGBA);
    if (!vel || !dye || !pres || !div) return null;

    host.appendChild(canvas);
    if (getComputedStyle(host).position === "static") host.style.position = "relative";

    function use(p, w, h) {
      gl.useProgram(p);
      var loc = gl.getAttribLocation(p, "p");
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      if (p.u.texel) gl.uniform2f(p.u.texel, 1 / w, 1 / h);
      return p;
    }
    function bind(p, name, tex, unit) {
      gl.activeTexture(gl.TEXTURE0 + unit);
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.uniform1i(p.u[name], unit);
    }
    function into(t) {
      gl.bindFramebuffer(gl.FRAMEBUFFER, t ? t.fbo : null);
      gl.viewport(0, 0, t ? t.w : canvas.width, t ? t.h : canvas.height);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }

    function splat(pr, x, y, amount, radius) {
      var p = use(progs.splat, pr.read.w, pr.read.h);
      bind(p, "src", pr.read.tex, 0);
      gl.uniform2f(p.u.at, x, y);
      gl.uniform3f(p.u.amount, amount[0], amount[1], amount[2]);
      gl.uniform1f(p.u.radius, radius);
      gl.uniform1f(p.u.aspect, 1.0);
      into(pr.write);
      pr.swap();
    }

    // Built on first use only, so a page that never inspects the field never
    // allocates it.
    var probeTarget = null;
    function sampleTarget() {
      if (!probeTarget) probeTarget = target(gl, 48, 48, gl.UNSIGNED_BYTE, gl.RGBA);
      return probeTarget;
    }

    var cold = rgbToVec(opts.cold || "#201e1d");
    var warm = rgbToVec(opts.warm || "#ec3013");
    var damp = 1;                    // 1 = free flowing, 0 = still
    var ducked = false;              // set once the muffle has driven it down
    var prev = 0, running = false, visible = false, raf = 0;
    var JACOBI = opts.jacobi || 18;

    function size() {
      var r = host.getBoundingClientRect();
      var dpr = Math.min(global.devicePixelRatio || 1, 1.5);
      canvas.width = Math.max(2, Math.round(r.width * dpr));
      canvas.height = Math.max(2, Math.round(r.height * dpr));
    }
    size();
    addEventListener("resize", size);

    function step(dt) {
      gl.disable(gl.BLEND);
      var p;

      // velocity carried along itself, losing a little as it goes
      p = use(progs.advect, SIM, SIM);
      bind(p, "src", vel.read.tex, 0);
      bind(p, "vel", vel.read.tex, 1);
      gl.uniform1f(p.u.dt, dt);
      gl.uniform1f(p.u.keep, 0.994 * damp);
      into(vel.write);
      vel.swap();

      p = use(progs.diverge, SIM, SIM);
      bind(p, "vel", vel.read.tex, 0);
      into(div);

      // Jacobi: each sweep is one more digit of the pressure field. Stop
      // early and the flow visibly gains and loses mass.
      for (var i = 0; i < JACOBI; i++) {
        p = use(progs.pressure, SIM, SIM);
        bind(p, "pres", pres.read.tex, 0);
        bind(p, "div", div.tex, 1);
        into(pres.write);
        pres.swap();
      }

      p = use(progs.project, SIM, SIM);
      bind(p, "pres", pres.read.tex, 0);
      bind(p, "vel", vel.read.tex, 1);
      into(vel.write);
      vel.swap();

      p = use(progs.advect, DYE, DYE);
      bind(p, "src", dye.read.tex, 0);
      bind(p, "vel", vel.read.tex, 1);
      gl.uniform1f(p.u.dt, dt);
      // Dissipation follows the cutoff too. Killing only the velocity left
      // the dye frozen in place and still spreading, so muffling looked like
      // a pause rather than like the motion going out of it.
      gl.uniform1f(p.u.keep, 0.970 + 0.0265 * damp);
      into(dye.write);
      dye.swap();

      p = use(progs.show, canvas.width, canvas.height);
      bind(p, "dye", dye.read.tex, 0);
      gl.uniform3f(p.u.cold, cold[0], cold[1], cold[2]);
      gl.uniform3f(p.u.warm, warm[0], warm[1], warm[2]);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.clearColor(0, 0, 0, 0);
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    }

    var t = 0;
    function frame(now) {
      if (!visible) { raf = 0; return; }
      var dt = prev ? Math.min(0.9, (now - prev) / 1000 * 60) : 1;
      prev = now;
      t += 0.01;

      // Climb back over about four seconds once the sweep stops driving it.
      // While the sweep is running every frame overwrites this, so the duck
      // still follows the cutoff exactly.
      if (ducked && damp < 1) damp = Math.min(1, damp + 0.004 * dt);

      // Two slow sources, so there is always something to carry. The fluid is
      // never pushed by the pointer: a hero that reacts to the mouse begs to
      // be played with, and the thing worth playing with on this page is the
      // Attack Lab.
      if (damp > 0.08) {
        var ax = 0.5 + Math.sin(t * 0.37) * 0.33;
        var ay = 0.42 + Math.cos(t * 0.29) * 0.22;
        // Velocity is in grid cells per step, and advection multiplies it by
        // one texel. At the first value tried, 520, a cell moved four texture
        // widths per frame: everything was flung past the clamped edge before
        // it could be seen, and the field read as empty. It wants tens.
        splat(vel, ax, ay, [Math.cos(t * 0.6) * 30 * damp, Math.sin(t * 0.53) * 30 * damp, 0], 0.030);
        splat(dye, ax, ay, [0.55 * damp, 0, 0], 0.022);
      }

      step(dt);
      raf = requestAnimationFrame(frame);
    }

    if ("IntersectionObserver" in global) {
      new IntersectionObserver(function (es) {
        visible = es[0].isIntersecting;
        prev = 0;
        if (visible && running && !raf) raf = requestAnimationFrame(frame);
      }, { threshold: 0.01 }).observe(host);
    } else {
      visible = true;
    }

    return {
      start: function () {
        if (running) return;
        running = true;
        visible = visible || !("IntersectionObserver" in global);
        if (!raf) raf = requestAnimationFrame(frame);
      },
      /* The muffle's cutoff, 1 down to 0. The fluid loses its momentum on the
       * same curve that rounds off the glyphs and dulls the note, and then
       * finds it again: the sweep ends at zero, and the first version left the
       * hero's background permanently dead after one play. The sweep is a duck,
       * not a switch. */
      setCutoff: function (cutoff) {
        damp = Math.max(0, Math.min(1, cutoff));
        ducked = true;
      },
      canvas: canvas,
      grid: { sim: SIM, dye: DYE, jacobi: JACOBI },
      /* How much dye is in the field. The simulation's own buffers are half
       * float, and WebGL1 will not hand those back as bytes - it returns
       * zeros and logs a format warning - so the dye is drawn through the
       * display shader into a small byte target and that is what is read.
       * Reading the canvas instead is never an option: a default framebuffer
       * is cleared once it has been composited. */
      sample: function () {
        var probe = sampleTarget();
        if (!probe) return null;
        var p = use(progs.show, probe.w, probe.h);
        bind(p, "dye", dye.read.tex, 0);
        gl.uniform3f(p.u.cold, cold[0], cold[1], cold[2]);
        gl.uniform3f(p.u.warm, warm[0], warm[1], warm[2]);
        gl.disable(gl.BLEND);
        into(probe);

        var px = new Uint8Array(4 * probe.w * probe.h);
        gl.readPixels(0, 0, probe.w, probe.h, gl.RGBA, gl.UNSIGNED_BYTE, px);
        gl.bindFramebuffer(gl.FRAMEBUFFER, null);

        var lit = 0, sum = 0;
        for (var i = 3; i < px.length; i += 4) {
          sum += px[i];
          if (px[i] > 8) lit++;
        }
        var n = probe.w * probe.h;
        return { lit: lit, of: n, meanAlpha: +(sum / n).toFixed(1), damp: damp };
      },
    };
  }

  global.MG_FLUID = { mount: mount, available: !REDUCED };
})(window);
