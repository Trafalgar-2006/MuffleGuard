/* Shared GPU plumbing, and the effects that sit on it.
 *
 * One tiny full-screen-quad renderer, reused by every shader on the site, so
 * each effect is a fragment shader and a uniform or two rather than another
 * copy of the same WebGL boilerplate.
 *
 * Contains:
 *   quad()     - the renderer
 *   scan()     - #6, a raymarched distance-field sweep over hidden text
 *   waveform() - #11, the noise floor drawn from live FFT data
 *
 * Everything is additive and guarded. No WebGL, no AudioContext, or reduced
 * motion, and the page is exactly what it was without them.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------ the quad */

  var VERT =
    "attribute vec2 p;varying vec2 uv;" +
    "void main(){uv=vec2(p.x*0.5+0.5,0.5-p.y*0.5);gl_Position=vec4(p,0.0,1.0);}";

  function compile(gl, type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      if (global.MG_FX_DEBUG) console.warn(gl.getShaderInfoLog(s));
      return null;
    }
    return s;
  }

  /* A canvas running one fragment shader. Returns null rather than throwing
   * if anything is unavailable, so every caller can simply fall back. */
  function quad(canvas, frag, uniformNames) {
    var gl = canvas.getContext("webgl", { premultipliedAlpha: false, alpha: true }) ||
             canvas.getContext("experimental-webgl");
    if (!gl) return null;

    var vs = compile(gl, gl.VERTEX_SHADER, VERT);
    var fs = compile(gl, gl.FRAGMENT_SHADER, frag);
    if (!vs || !fs) return null;

    var prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return null;
    gl.useProgram(prog);

    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    var loc = gl.getAttribLocation(prog, "p");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

    var u = {};
    (uniformNames || []).forEach(function (n) { u[n] = gl.getUniformLocation(prog, n); });

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    return {
      gl: gl, u: u,
      draw: function () {
        gl.clearColor(0, 0, 0, 0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      },
      texture: function (image) {
        var t = gl.createTexture();
        gl.bindTexture(gl.TEXTURE_2D, t);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image);
        return t;
      },
    };
  }

  /* ------------------------------------------- #6 the distance-field scan
   *
   * The classifier reading a message is a search, so the sweep is drawn as
   * one. For every pixel the shader marches along x through the text mask
   * looking for the nearest glyph edge, and the distance it travels before
   * finding one becomes the colour: close to ink reads hot, open space reads
   * cold. That is a raymarch over a distance field rather than a gradient
   * sliding across a mask, and the difference is visible — the sweep hugs the
   * letterforms instead of cutting a straight line through them.
   */

  var SCAN_FRAG = [
    "precision mediump float;",
    "varying vec2 uv;",
    "uniform sampler2D tex;",
    "uniform vec2 texel;",
    "uniform float sweep;",     // 0..1, where the scan front is
    "",
    "float ink(vec2 c){ return texture2D(tex, c).a; }",
    "",
    "// March along x until the mask is hit; return how far we got.",
    "float march(vec2 from){",
    "  float d = 1.0;",
    "  for(int i=0;i<24;i++){",
    "    float step = float(i);",
    "    vec2 a = from + vec2(texel.x*step, 0.0);",
    "    vec2 b = from - vec2(texel.x*step, 0.0);",
    "    if(ink(a) > 0.35 || ink(b) > 0.35){ d = step/24.0; break; }",
    "  }",
    "  return d;",
    "}",
    "",
    "void main(){",
    "  float here = ink(uv);",
    "  float dist = march(uv);",
    "  // The front, and a short tail behind it.",
    "  float front = smoothstep(0.045, 0.0, abs(uv.x - sweep));",
    "  float tail  = smoothstep(0.30, 0.0, sweep - uv.x) * step(uv.x, sweep);",
    "",
    "  // Nearness to ink, so the heat follows the glyph shapes.",
    "  float heat = (1.0 - dist);",
    "  vec3 cold = vec3(0.09, 0.80, 1.0);",
    "  vec3 hot  = vec3(0.93, 0.19, 0.07);",
    "  vec3 col  = mix(cold, hot, heat*heat);",
    "",
    "  float revealed = max(here * tail * 0.95, 0.0);",
    "  float edge = front * (0.25 + heat * 0.75);",
    "  float a = clamp(revealed + edge, 0.0, 1.0);",
    "  gl_FragColor = vec4(col, a);",
    "}",
  ].join("\n");

  function scan(host, text) {
    if (REDUCED || !host) return null;

    var rect = host.getBoundingClientRect();
    var w = Math.max(32, Math.ceil(rect.width));
    var h = Math.max(20, Math.ceil(rect.height));
    var dpr = Math.min(global.devicePixelRatio || 1, 2);

    // Draw the hidden text into a mask the shader can march through.
    var src = document.createElement("canvas");
    src.width = w * dpr; src.height = h * dpr;
    var c2 = src.getContext("2d");
    if (!c2) return null;
    c2.scale(dpr, dpr);
    c2.font = "500 12px ui-monospace, SFMono-Regular, Menlo, monospace";
    c2.fillStyle = "#fff";
    c2.textBaseline = "middle";
    var words = String(text || host.textContent || "").slice(0, 150);
    c2.fillText(words, 6, h / 2);

    var canvas = document.createElement("canvas");
    canvas.width = src.width; canvas.height = src.height;
    canvas.style.cssText =
      "position:absolute;left:0;top:0;width:" + w + "px;height:" + h +
      "px;pointer-events:none;opacity:0;transition:opacity .25s";
    if (getComputedStyle(host).position === "static") host.style.position = "relative";
    host.appendChild(canvas);

    var q = quad(canvas, SCAN_FRAG, ["tex", "texel", "sweep"]);
    if (!q) { canvas.remove(); return null; }
    q.texture(src);
    q.gl.uniform2f(q.u.texel, 1 / canvas.width, 1 / canvas.height);

    var running = false;
    function run() {
      if (running) return;
      running = true;
      canvas.style.opacity = "1";
      var t0 = 0;
      function frame(t) {
        if (!t0) t0 = t;
        var k = Math.min(1, (t - t0) / 1500);
        q.gl.uniform1f(q.u.sweep, k * 1.25 - 0.1);
        q.draw();
        if (k < 1) requestAnimationFrame(frame);
        else { canvas.style.opacity = "0"; running = false; }
      }
      requestAnimationFrame(frame);
    }
    return { run: run, canvas: canvas };
  }

  /* ------------------------------------------------ #11 the noise floor
   *
   * A quiet waveform along the foot of the hero, drawn from real FFT data off
   * the same audio graph the muffle uses. When the muffle sweeps, the high
   * bands genuinely collapse, because it is the same filter: this is a
   * picture of the audio, not an animation timed to look like one.
   *
   * With the sound off there is nothing to analyse, so it draws a flat
   * resting line instead of pretending.
   */

  function waveform(host) {
    if (!host || REDUCED) return null;
    var canvas = document.createElement("canvas");
    var w = host.clientWidth || 600, h = 40;
    var dpr = Math.min(global.devicePixelRatio || 1, 2);
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.cssText = "display:block;width:100%;height:" + h + "px;opacity:.55";
    host.appendChild(canvas);
    var ctx = canvas.getContext("2d");
    if (!ctx) { canvas.remove(); return null; }
    ctx.scale(dpr, dpr);

    var analyser = null, bins = null;

    function attach(audioCtx, node) {
      if (!audioCtx || analyser) return;
      analyser = audioCtx.createAnalyser();
      analyser.fftSize = 128;
      analyser.smoothingTimeConstant = 0.78;
      bins = new Uint8Array(analyser.frequencyBinCount);
      node.connect(analyser);
    }

    function frame() {
      ctx.clearRect(0, 0, w, h);
      var mid = h / 2;
      ctx.beginPath();
      if (analyser) {
        analyser.getByteFrequencyData(bins);
        for (var i = 0; i < bins.length; i++) {
          var x = (i / (bins.length - 1)) * w;
          var y = mid - (bins[i] / 255) * (h * 0.44);
          i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
        }
      } else {
        ctx.moveTo(0, mid); ctx.lineTo(w, mid);   // resting: nothing to hear
      }
      ctx.strokeStyle = "rgba(236,48,19,.85)";
      ctx.lineWidth = 1.5;
      ctx.stroke();
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
    return { attach: attach };
  }

  global.MG_FX = { quad: quad, scan: scan, waveform: waveform, available: !REDUCED };
})(window);
