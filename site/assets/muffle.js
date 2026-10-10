/* The muffle, as a signal rather than as a metaphor.
 *
 * The product is named after what happens to sound when you put something in
 * front of it: the high frequencies go first and the shape of the thing is
 * left behind. That is also, exactly, what happens to a letterform when you
 * low-pass filter an image of it. So the injected sentence is filtered twice
 * from one number:
 *
 *   cutoff 1 -> 0   drives a BiquadFilterNode lowpass on an audio tone
 *                   AND the sigma of a Gaussian convolution in a GLSL shader
 *
 * A Gaussian convolution is a low-pass filter. Widening its kernel attenuates
 * high spatial frequencies, which is why the sharp corners of the glyphs round
 * off and the sentence turns into its own silhouette. It is not a CSS blur
 * standing in for the idea; it is the idea.
 *
 * Everything here is additive. No WebGL, no AudioContext, reduced motion, or a
 * browser that refuses any of it: the page keeps the strike-through it already
 * had and nothing is lost but the flourish.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------ audio: the real filter */

  var audio = {
    ctx: null,
    on: false,       // muted until somebody asks for it
    ready: false,
  };

  function buildAudio() {
    if (audio.ready) return true;
    var AC = global.AudioContext || global.webkitAudioContext;
    if (!AC) return false;
    try {
      audio.ctx = new AC();
    } catch (e) {
      return false;
    }
    audio.ready = true;
    return true;
  }

  /* One note, played through a lowpass whose cutoff falls over the same
   * duration the sentence is being struck out. A sawtooth because it is
   * harmonically rich: there has to be something up there for the filter to
   * take away, or the muffle is inaudible. */
  function playMuffle(ms) {
    if (!audio.on || !buildAudio()) return;
    var ctx = audio.ctx;
    if (ctx.state === "suspended") ctx.resume();

    var now = ctx.currentTime;
    var seconds = (ms || 1200) / 1000;

    var osc = ctx.createOscillator();
    osc.type = "sawtooth";
    osc.frequency.value = 174;

    var filter = ctx.createBiquadFilter();
    filter.type = "lowpass";
    filter.Q.value = 1.1;
    filter.frequency.setValueAtTime(7200, now);
    // Exponential, because pitch and brightness are heard logarithmically: a
    // linear sweep sounds like it stops moving halfway down.
    filter.frequency.exponentialRampToValueAtTime(190, now + seconds);

    var gain = ctx.createGain();
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.exponentialRampToValueAtTime(0.085, now + 0.04);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + seconds + 0.25);

    osc.connect(filter).connect(gain).connect(ctx.destination);
    // The noise floor analyses this same node, so what it draws is the
    // filter actually working rather than a shape timed to match it.
    if (global.MG_FX_SINK) global.MG_FX_SINK(ctx, gain);
    osc.start(now);
    osc.stop(now + seconds + 0.3);
  }

  /* -------------------------------------------------- shader: same filter */

  var VERT =
    "attribute vec2 p;varying vec2 uv;" +
    "void main(){uv=vec2(p.x*0.5+0.5,0.5-p.y*0.5);gl_Position=vec4(p,0.0,1.0);}";

  /* Separable Gaussian, horizontal pass only: a sentence is a signal that runs
   * left to right, so that is the axis whose high frequencies carry the
   * letterforms. sigma is the control, and sigma is 1 - cutoff. */
  var FRAG =
    "precision mediump float;" +
    "varying vec2 uv;" +
    "uniform sampler2D tex;" +
    "uniform vec2 texel;" +
    "uniform float sigma;" +
    "void main(){" +
    "  if(sigma<0.4){gl_FragColor=texture2D(tex,uv);return;}" +
    "  float wsum=0.0;vec4 acc=vec4(0.0);" +
    "  for(int i=-12;i<=12;i++){" +
    "    float x=float(i);" +
    "    float w=exp(-(x*x)/(2.0*sigma*sigma));" +
    "    acc+=texture2D(tex,uv+vec2(texel.x*x,0.0))*w;" +
    "    wsum+=w;" +
    "  }" +
    "  gl_FragColor=acc/wsum;" +
    "}";

  function compile(gl, type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
  }

  /* Draw the sentence into a 2D canvas, hand that to the GPU as a texture, and
   * filter it there. Rendering the text ourselves is what makes it a signal we
   * own rather than glyphs the browser has already rasterised out of reach. */
  function buildShader(el) {
    var gl, canvas, program, texture, uSigma, uTexel, dpr;

    function textToCanvas() {
      var rect = el.getBoundingClientRect();
      var w = Math.max(16, Math.ceil(rect.width));
      var h = Math.max(12, Math.ceil(rect.height));
      dpr = Math.min(global.devicePixelRatio || 1, 2);

      var src = document.createElement("canvas");
      src.width = w * dpr;
      src.height = h * dpr;
      var c = src.getContext("2d");
      if (!c) return null;
      c.scale(dpr, dpr);

      var cs = getComputedStyle(el);
      c.font = cs.fontWeight + " " + cs.fontSize + " " + cs.fontFamily;
      c.textBaseline = "middle";
      c.fillStyle = cs.color;
      c.fillText(el.textContent, 0, h / 2);
      return { src: src, w: w, h: h };
    }

    var made = textToCanvas();
    if (!made) return null;

    canvas = document.createElement("canvas");
    canvas.width = made.src.width;
    canvas.height = made.src.height;
    canvas.style.cssText =
      "position:absolute;left:0;top:0;width:" + made.w + "px;height:" + made.h +
      "px;pointer-events:none;opacity:0";
    el.parentElement.appendChild(canvas);

    gl = canvas.getContext("webgl", { premultipliedAlpha: false, antialias: true }) ||
         canvas.getContext("experimental-webgl");
    if (!gl) { canvas.remove(); return null; }

    var vs = compile(gl, gl.VERTEX_SHADER, VERT);
    var fs = compile(gl, gl.FRAGMENT_SHADER, FRAG);
    if (!vs || !fs) { canvas.remove(); return null; }

    program = gl.createProgram();
    gl.attachShader(program, vs);
    gl.attachShader(program, fs);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) { canvas.remove(); return null; }
    gl.useProgram(program);

    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    var loc = gl.getAttribLocation(program, "p");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

    texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, made.src);

    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    uSigma = gl.getUniformLocation(program, "sigma");
    uTexel = gl.getUniformLocation(program, "texel");
    gl.uniform2f(uTexel, 1 / canvas.width, 1 / canvas.height);

    return {
      canvas: canvas,
      // cutoff 1 = untouched, 0 = fully muffled
      draw: function (cutoff) {
        var sigma = (1 - cutoff) * 6.2;   // enough to round the glyphs, not erase them
        gl.uniform1f(uSigma, sigma);
        gl.clearColor(0, 0, 0, 0);
        gl.clear(gl.COLOR_BUFFER_BIT);
        gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      },
      show: function () { canvas.style.opacity = "1"; el.style.opacity = "0"; },
      hide: function () { canvas.style.opacity = "0"; el.style.opacity = ""; },
    };
  }

  /* ------------------------------------------------------- the public bit */

  var shader = null, building = false, running = false;

  function ensureShader(el) {
    if (shader || building || REDUCED) return shader;
    building = true;
    try { shader = buildShader(el); } catch (e) { shader = null; }
    building = false;
    return shader;
  }

  /* Sweep both filters from one number over the same span of time. */
  function run(el, ms) {
    if (running) return;
    ms = ms || 1200;

    // Sound is not motion. Somebody who asked for reduced motion still gets
    // the audio if they press the button for it, because they pressed the
    // button; what they do not get is the picture moving at them.
    playMuffle(ms);
    if (REDUCED) return;

    var sh = ensureShader(el);
    if (!sh) return;                       // audio alone is still worth having

    running = true;
    sh.show();
    var started = 0;
    function frame(t) {
      if (!started) started = t;
      var k = Math.min(1, (t - started) / ms);
      // ease so most of the brightness goes early, as a filter sweep sounds
      var cutoff = 1 - (1 - Math.pow(1 - k, 2.2));
      sh.draw(cutoff);
      if (k < 1) {
        requestAnimationFrame(frame);
      } else {
        sh.draw(0);
        running = false;
      }
    }
    requestAnimationFrame(frame);
  }

  function reset(el) {
    if (shader) { shader.hide(); }
    running = false;
    if (el) el.style.opacity = "";
  }

  /* The toggle. Muted by default: sound that arrives uninvited is a reason to
   * close a tab. Built only once we know an AudioContext exists at all. */
  function mountToggle(host) {
    if (!host || !(global.AudioContext || global.webkitAudioContext)) return;
    var b = document.createElement("button");
    b.type = "button";
    b.setAttribute("aria-pressed", "false");
    b.className = "mg-sound";
    b.innerHTML = '<span aria-hidden="true">▶</span> Hear it muffle';
    b.addEventListener("click", function () {
      audio.on = !audio.on;
      b.setAttribute("aria-pressed", String(audio.on));
      b.innerHTML = audio.on
        ? '<span aria-hidden="true">■</span> Sound on'
        : '<span aria-hidden="true">▶</span> Hear it muffle';
      if (audio.on) {
        buildAudio();
        if (audio.ctx && audio.ctx.state === "suspended") audio.ctx.resume();
        var el = document.querySelector("[data-type]");
        if (el) run(el, 1200);             // play it the moment they ask
      }
    });
    host.appendChild(b);
  }

  global.MG_MUFFLE = { run: run, reset: reset, mountToggle: mountToggle, available: !REDUCED };
})(window);
