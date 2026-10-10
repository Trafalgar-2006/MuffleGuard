/* Two effects where the force is the point.
 *
 *   swarm()   - #3, the request as a body of particles that the policy gate
 *               pushes back, integrated rather than keyframed
 *   sandbox() - #7, tool calls falling into Allow / Ask / Block, where a
 *               dangerous call is literally heavier
 *
 * Both are real integrations: positions come out of forces and a timestep,
 * not out of a tween. That is the whole reason they are here — a refusal that
 * is felt as a force says something a fade cannot.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* Both of these drew in rgba(32,30,29), which is the light theme's ink. In
   * dark mode that is the panel colour almost exactly, so the swarm and every
   * tool call in the sandbox were invisible. Canvas has no CSS variables, so
   * the values are read from the document and re-read when the theme flips. */
  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function rgba(hex, alpha) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
    if (!m) return "rgba(32,30,29," + alpha + ")";
    return "rgba(" + parseInt(m[1], 16) + "," + parseInt(m[2], 16) + "," +
      parseInt(m[3], 16) + "," + alpha + ")";
  }

  function ink(alpha) { return rgba(cssVar("--mg-ink", "#201e1d"), alpha); }
  function hot(alpha) { return rgba(cssVar("--mg-hot", "#ec3013"), alpha); }

  /* Call back whenever the theme toggle fires, so a running canvas repaints
   * rather than waiting for a reload. */
  function onTheme(fn) {
    if (!global.MutationObserver) return;
    new MutationObserver(fn).observe(document.documentElement, {
      attributes: true, attributeFilter: ["data-theme"],
    });
  }

  /* ---------------------------------------------- #3 the request, as mass
   *
   * A few hundred particles drift toward the tool call. The gate carries a
   * repulsion field with an inverse-square falloff, so when it closes the
   * swarm does not stop: it is pushed, it piles up against the field, and the
   * ones with the most momentum get thrown furthest back. The refusal is a
   * force rather than a state change, which is the honest shape of it.
   */
  function swarm(host, opts) {
    if (!host || REDUCED) return null;
    opts = opts || {};
    var canvas = document.createElement("canvas");
    var w = host.clientWidth || 420, h = opts.height || 150;
    var dpr = Math.min(global.devicePixelRatio || 1, 2);
    canvas.width = w * dpr; canvas.height = h * dpr;
    canvas.style.cssText = "display:block;width:100%;height:" + h + "px";
    host.appendChild(canvas);
    var ctx = canvas.getContext("2d");
    if (!ctx) { canvas.remove(); return null; }
    ctx.scale(dpr, dpr);

    var N = 260;
    var ps = [];
    var gateX = w * 0.72;
    var blocked = false, running = false, raf = 0;

    function seed() {
      ps.length = 0;
      for (var i = 0; i < N; i++) {
        ps.push({
          x: -Math.random() * w * 0.4,
          y: h / 2 + (Math.random() - 0.5) * h * 0.55,
          vx: 0.7 + Math.random() * 0.8,
          vy: (Math.random() - 0.5) * 0.25,
          m: 0.6 + Math.random() * 0.8,      // mass, so they do not move as one
          done: false,
        });
      }
    }

    function step() {
      ctx.clearRect(0, 0, w, h);

      // the gate
      ctx.strokeStyle = blocked ? hot(0.95) : ink(0.3);
      ctx.lineWidth = blocked ? 3 : 2;
      ctx.beginPath(); ctx.moveTo(gateX, 12); ctx.lineTo(gateX, h - 12); ctx.stroke();

      for (var i = 0; i < ps.length; i++) {
        var p = ps[i];
        // Drift toward the gate.
        p.vx += 0.035 / p.m;

        if (blocked) {
          // Inverse-square repulsion from the gate plane. Close in it is
          // violent, far out it is nothing, which is what makes the pile-up
          // look like pressure rather than a bounce.
          var d = p.x - gateX;
          var r = Math.max(14, Math.abs(d));
          var f = 2600 / (r * r);
          p.vx -= (d < 0 ? f : -f) / p.m;
          p.vy += (p.y - h / 2) * 0.0016 * f;
        }

        p.vx *= 0.985; p.vy *= 0.985;
        p.x += p.vx; p.y += p.vy;

        if (!blocked && p.x > gateX) p.done = true;
        if (p.x < -w * 0.6) { p.x = -Math.random() * 40; p.vx = 0.7; }

        var near = blocked && p.x > gateX - 90;
        ctx.fillStyle = p.done
          ? ink(0.3)
          : near ? hot(0.85) : ink(0.62);
        ctx.fillRect(p.x, p.y, 2.2, 2.2);
      }
      raf = requestAnimationFrame(step);
    }

    return {
      start: function (isBlocked) {
        blocked = !!isBlocked;
        seed();
        if (!running) { running = true; step(); }
      },
      block: function () { blocked = true; },
      stop: function () { cancelAnimationFrame(raf); running = false; },
      canvas: canvas,
    };
  }

  /* ------------------------------------------- #7 the policy, as weight
   *
   * Tool calls drop into three bins. A call matching a dangerous pattern is
   * given real density, so it falls harder and is genuinely more work to
   * nudge into Allow: the policy weighting is in the physics rather than
   * written beside it. Drag one and find out.
   */
  function sandbox(host) {
    if (!host || REDUCED || !global.Matter) return null;
    var M = global.Matter;
    var w = host.clientWidth || 520, h = 230;

    var engine = M.Engine.create();
    engine.gravity.y = 0.9;

    var render = M.Render.create({
      element: host,
      engine: engine,
      options: {
        width: w, height: h, wireframes: false,
        background: "transparent", pixelRatio: Math.min(global.devicePixelRatio || 1, 2),
      },
    });

    var wall = function (x, y, ww, hh) {
      return M.Bodies.rectangle(x, y, ww, hh, {
        isStatic: true, render: { fillStyle: ink(0.22) },
      });
    };
    var floorY = h - 10;
    var parts = [wall(w / 2, floorY, w, 20), wall(-5, h / 2, 20, h), wall(w + 5, h / 2, 20, h)];
    // bin dividers
    parts.push(wall(w / 3, h - 48, 3, 76), wall((w / 3) * 2, h - 48, 3, 76));
    M.Composite.add(engine.world, parts);

    var CALLS = [
      { label: "inbox_read", danger: false },
      { label: "files_read", danger: false },
      { label: "email_send", danger: true },
      { label: "http_post", danger: true },
      { label: "shell_run", danger: true },
      { label: "web_fetch", danger: false },
    ];

    function drop(i) {
      var c = CALLS[i % CALLS.length];
      // Density is the policy: a dangerous call weighs several times more,
      // so it resists being pushed into Allow.
      var body = M.Bodies.rectangle(
        40 + Math.random() * (w - 80), -30, 96, 30,
        {
          restitution: 0.18,
          friction: 0.55,
          density: c.danger ? 0.0075 : 0.0012,
          render: {
            fillStyle: c.danger ? cssVar("--mg-hot", "#ec3013") : cssVar("--mg-ink", "#201e1d"),
            strokeStyle: "transparent",
          },
          plugin: { danger: c.danger },
          label: c.label,
        }
      );
      M.Composite.add(engine.world, body);
      // Keep the world small; the oldest call leaves when a new one lands.
      var bodies = M.Composite.allBodies(engine.world).filter(function (b) { return !b.isStatic; });
      if (bodies.length > 9) M.Composite.remove(engine.world, bodies[0]);
    }

    var mouse = M.Mouse.create(render.canvas);
    var drag = M.MouseConstraint.create(engine, {
      mouse: mouse,
      constraint: { stiffness: 0.18, render: { visible: false } },
    });
    M.Composite.add(engine.world, drag);
    // Let the page keep scrolling over the sandbox.
    mouse.element.removeEventListener("wheel", mouse.mousewheel);

    // Matter draws shapes, not words. Without the tool name on the box this
    // is an abstract toy; with it, the weight you feel dragging one is the
    // policy for that specific call.
    M.Events.on(render, "afterRender", function () {
      var c = render.context;
      c.save();
      c.font = "700 11px Archivo, system-ui, sans-serif";
      c.textAlign = "center";
      c.textBaseline = "middle";
      M.Composite.allBodies(engine.world).forEach(function (b) {
        if (b.isStatic || !b.label || b.label === "Body") return;
        c.save();
        c.translate(b.position.x, b.position.y);
        c.rotate(b.angle);
        c.fillStyle = (b.plugin && b.plugin.danger)
          ? "#fff"
          : cssVar("--mg-bg", "#f3f2f2");
        c.fillText(b.label, 0, 0);
        c.restore();
      });
      c.restore();
    });

    var runner = M.Runner.create();
    var started = false;

    onTheme(function () {
      var inkNow = cssVar("--mg-ink", "#201e1d");
      var hotNow = cssVar("--mg-hot", "#ec3013");
      M.Composite.allBodies(engine.world).forEach(function (b) {
        if (b.isStatic) b.render.fillStyle = ink(0.22);
        else b.render.fillStyle = (b.plugin && b.plugin.danger) ? hotNow : inkNow;
      });
    });

    return {
      start: function () {
        if (started) return;
        started = true;
        M.Render.run(render);
        M.Runner.run(runner, engine);
        var n = 0;
        var iv = setInterval(function () {
          drop(n++);
          if (n > 7) clearInterval(iv);
        }, 620);
      },
      stop: function () {
        M.Render.stop(render);
        M.Runner.stop(runner);
      },
      canvas: render.canvas,
    };
  }

  global.MG_PHYS = { swarm: swarm, sandbox: sandbox, available: !REDUCED };
})(window);
