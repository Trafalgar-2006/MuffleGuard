/* The three dimensional pieces.
 *
 *   chain()  - #5, the hash chain as links, which break and drift when an
 *              entry is edited
 *   graph()  - #4, provenance laid out by a real force simulation
 *   flight() - #10, one scene the camera flies through as you scroll
 *
 * They share a scene helper because they share three problems: a renderer
 * that only runs while it is on screen, one that resizes with its host, and
 * colours that have to follow the theme toggle.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function THREE() { return global.THREE; }

  function cssVar(name, fallback) {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  /* Dark mode flips --mg-ink from near-black to near-white, so a material
   * that hardcodes ink is invisible on one of the two themes. Each material
   * carries the role it was painted with and a theme flip repaints by role.
   * A material can be held, which is how a link stays red after a tamper. */
  var ROLES = {
    ink: function () { return cssVar("--mg-ink", "#201e1d"); },
    hot: function () { return cssVar("--mg-hot", "#ec3013"); },
    gold: function () { return "#c89b3c"; },
    faint: function () { return "#9a9794"; },
  };
  function paint(mat, role) {
    mat.userData.role = role;
    mat.color.set(ROLES[role]());
    return mat;
  }

  /* A renderer bound to a host: paused off screen, resized with the host,
   * repainted when the theme flips. */
  function stage(host, height, camZ) {
    if (!host || REDUCED || !THREE()) return null;
    var T = THREE();
    var w = host.clientWidth || 600, h = height || 320;

    var renderer;
    try {
      renderer = new T.WebGLRenderer({ antialias: true, alpha: true });
    } catch (e) {
      return null;                                 // no GL here: caller falls back
    }
    renderer.setPixelRatio(Math.min(global.devicePixelRatio || 1, 2));
    renderer.setSize(w, h, false);
    renderer.domElement.style.cssText = "display:block;width:100%;height:" + h + "px";
    host.appendChild(renderer.domElement);

    var scene = new T.Scene();
    var camera = new T.PerspectiveCamera(45, w / h, 0.1, 400);
    camera.position.set(0, 0, camZ || 26);

    scene.add(new T.AmbientLight(0xffffff, 0.9));
    var key = new T.DirectionalLight(0xffffff, 0.85);
    key.position.set(6, 10, 14);
    scene.add(key);

    var onFrame = null, visible = false, raf = 0;

    function loop(now) {
      if (!visible) { raf = 0; return; }
      if (onFrame) onFrame(now || 0);
      renderer.render(scene, camera);
      raf = requestAnimationFrame(loop);
    }

    if ("IntersectionObserver" in global) {
      new IntersectionObserver(function (es) {
        visible = es[0].isIntersecting;
        if (visible && !raf) raf = requestAnimationFrame(loop);
      }, { threshold: 0.02 }).observe(host);
    } else {
      visible = true;
      raf = requestAnimationFrame(loop);
    }

    addEventListener("resize", function () {
      var nw = host.clientWidth || w;
      camera.aspect = nw / h;
      camera.updateProjectionMatrix();
      renderer.setSize(nw, h, false);
    });

    if (global.MutationObserver) {
      new MutationObserver(function () {
        scene.traverse(function (o) {
          var m = o.material;
          if (!m || !m.userData.role || m.userData.held) return;
          m.color.set(ROLES[m.userData.role]());
        });
        if (!visible) renderer.render(scene, camera);   // keep the still frame right
      }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    }

    return {
      T: T, scene: scene, camera: camera, renderer: renderer,
      set frame(f) { onFrame = f; },
      get frame() { return onFrame; },
    };
  }

  /* -------------------------------------------------- #5 the hash chain
   *
   * Each entry is a link, hooked to the one before it. Editing an entry
   * unhooks it: everything downstream loses what it was hanging from and
   * drifts, because that is what has actually happened to the chain. Once one
   * entry's hash input is wrong, nothing after it is anchored to anything.
   *
   * The links before the edit keep hanging where they were. That part matters.
   * Tamper-evidence means the earlier record is still good, and a version
   * where the whole chain let go would be a prettier lie.
   */
  function chain(host, count) {
    var st = stage(host, 280, 26);
    if (!st) return null;
    var T = st.T;

    var n = count || 11;
    var links = [];
    var geo = new T.TorusGeometry(0.92, 0.2, 10, 26);
    var span = Math.min(2.0, 22 / n);

    for (var i = 0; i < n; i++) {
      var mat = paint(new T.MeshStandardMaterial({
        roughness: 0.5, metalness: 0.2, transparent: true, opacity: 0.96,
      }), "ink");
      var m = new T.Mesh(geo, mat);
      m.position.set((i - (n - 1) / 2) * span, 0, 0);
      m.rotation.y = (i % 2) * Math.PI / 2;      // alternate, as links interlock
      st.scene.add(m);
      links.push({ mesh: m, home: m.position.clone(), v: new T.Vector3(), loose: false });
    }

    var t = 0, prev = 0;
    st.frame = function (now) {
      // Scaled by real elapsed time, not by frames. The first version used a
      // fixed per-frame step and fell twice as fast on a 120Hz screen as on
      // the machine it was tuned on.
      var step = prev ? Math.min(3, Math.max(0.4, (now - prev) / 16.7)) : 1;
      prev = now;
      t += 0.016 * step;

      for (var i = 0; i < links.length; i++) {
        var L = links[i];
        if (L.loose) {
          // Unanchored: gravity, a tumble, no spring home. Slow enough to
          // watch them go, which is the whole point of showing it.
          L.v.y -= 0.0016 * step;
          L.mesh.position.addScaledVector(L.v, step);
          L.mesh.rotation.x += 0.022 * step;
          L.mesh.rotation.z += 0.015 * step;
          L.mesh.material.opacity = Math.max(0.05, L.mesh.material.opacity - 0.0022 * step);
        } else {
          // Held: breathe on the spot, so the chain reads as under tension.
          L.mesh.position.y = L.home.y + Math.sin(t * 1.3 + i * 0.5) * 0.06;
          L.mesh.rotation.y += 0.004 * step;
        }
      }
    };

    var timers = [];
    function clearTimers() { timers.forEach(clearTimeout); timers = []; }

    function hold(mat, role) { mat.userData.held = true; mat.color.set(ROLES[role]()); }
    function release(mat) { mat.userData.held = false; mat.color.set(ROLES[mat.userData.role]()); }

    return {
      /* Verified: a gold settle, link by link, left to right. Verification is
       * sequential, each link checked against the one before it, so the
       * animation runs in that order rather than all at once. */
      verify: function () {
        clearTimers();
        links.forEach(function (L, i) {
          if (L.loose) return;
          timers.push(setTimeout(function () {
            hold(L.mesh.material, "gold");
            timers.push(setTimeout(function () { release(L.mesh.material); }, 520));
          }, i * 60));
        });
      },
      tamper: function (index) {
        clearTimers();
        var at = typeof index === "number" ? index : Math.floor(n / 2);
        links.forEach(function (L, i) {
          if (i < at) return;
          if (i === at) hold(L.mesh.material, "hot");
          L.loose = true;
          L.v.set((Math.random() - 0.25) * 0.05, Math.random() * 0.03, (Math.random() - 0.5) * 0.04);
        });
        return at;
      },
      reset: function () {
        clearTimers();
        links.forEach(function (L) {
          L.loose = false;
          L.v.set(0, 0, 0);
          L.mesh.position.copy(L.home);
          L.mesh.material.opacity = 0.96;
          release(L.mesh.material);
        });
      },
      count: n,
      /* What the chain is actually doing, so the claim can be checked rather
       * than taken on the caption's word. */
      state: function () {
        return links.map(function (L) {
          return { loose: L.loose, dy: +(L.mesh.position.y - L.home.y).toFixed(3) };
        });
      },
    };
  }

  /* ------------------------------------------ #4 provenance, laid out
   *
   * Nodes repel, edges pull, and the layout is whatever those forces settle
   * into rather than positions anyone typed in. The two traced edges get a
   * much stiffer spring than the rest, so the path from the outbound call
   * back to the email that supplied its target pulls itself tight and ends up
   * the shortest line in the picture. The graph arranges itself around the
   * finding.
   */
  function graph(host) {
    var st = stage(host, 300, 30);
    if (!st) return null;
    var T = st.T;

    var NODES = [
      { id: "you", kind: "user" },
      { id: "inbox", kind: "tool" },
      { id: "mail4", kind: "untrusted" },
      { id: "mail5", kind: "untrusted" },
      { id: "env", kind: "private" },
      { id: "call", kind: "call" },
      { id: "evil", kind: "target" },
    ];
    var EDGES = [
      ["you", "inbox", 0.02], ["inbox", "mail4", 0.02], ["inbox", "mail5", 0.02],
      ["you", "env", 0.02], ["call", "env", 0.02],
      ["mail5", "evil", 0.17], ["evil", "call", 0.13],   // the traced path
    ];
    var ROLE_OF = {
      user: "ink", tool: "ink", call: "ink",
      untrusted: "hot", target: "hot", private: "gold",
    };

    var byId = {};
    NODES.forEach(function (nd, i) {
      var a = (i / NODES.length) * Math.PI * 2;
      nd.p = new T.Vector3(Math.cos(a) * 7, Math.sin(a) * 4.5, (Math.random() - 0.5) * 5);
      nd.v = new T.Vector3();
      var big = nd.kind === "target" || nd.kind === "call";
      var mat = paint(new T.MeshStandardMaterial({ roughness: 0.45, metalness: 0.1 }), ROLE_OF[nd.kind]);
      nd.mesh = new T.Mesh(new T.SphereGeometry(big ? 0.78 : 0.54, 18, 14), mat);
      st.scene.add(nd.mesh);
      byId[nd.id] = nd;
    });

    var lines = EDGES.map(function (e) {
      var traced = e[2] > 0.1;
      var mat = paint(
        new T.LineBasicMaterial({ transparent: true, opacity: traced ? 0.95 : 0.3 }),
        traced ? "hot" : "faint"
      );
      var l = new T.Line(new T.BufferGeometry().setFromPoints([new T.Vector3(), new T.Vector3()]), mat);
      st.scene.add(l);
      return l;
    });

    var spin = 0;
    st.frame = function () {
      var i, j;
      for (i = 0; i < NODES.length; i++) {
        for (j = i + 1; j < NODES.length; j++) {
          var a = NODES[i], b = NODES[j];
          var d = a.p.clone().sub(b.p);
          var r = Math.max(1.5, d.length());
          d.normalize().multiplyScalar(4.8 / (r * r));
          a.v.add(d);
          b.v.sub(d);
        }
      }
      EDGES.forEach(function (e) {
        var a = byId[e[0]], b = byId[e[1]];
        var d = b.p.clone().sub(a.p);
        var pull = (d.length() - 4.8) * e[2];
        d.normalize().multiplyScalar(pull);
        a.v.add(d);
        b.v.sub(d);
      });
      NODES.forEach(function (nd) {
        nd.v.multiplyScalar(0.85);
        nd.p.add(nd.v);
        nd.p.multiplyScalar(0.9985);               // a gentle pull to the middle
        nd.mesh.position.copy(nd.p);
      });
      EDGES.forEach(function (e, k) {
        lines[k].geometry.setFromPoints([byId[e[0]].p, byId[e[1]].p]);
        lines[k].geometry.attributes.position.needsUpdate = true;
      });
      spin += 0.0021;
      st.camera.position.x = Math.sin(spin) * 30;
      st.camera.position.z = Math.cos(spin) * 30;
      st.camera.lookAt(0, 0, 0);
    };

    return { nodes: NODES.length, edges: EDGES.length };
  }

  /* ------------------------------------------- #10 the scrolled flight
   *
   * One scene, four stations, and a camera that travels a Catmull-Rom spline
   * as the section scrolls. The stations are the pipeline in order, so
   * scrolling is travelling through it rather than paging past pictures of
   * it. The route is drawn before you take it, which is the only reason the
   * movement reads as a path rather than as drift.
   */
  function flight(host, labelEl) {
    var st = stage(host, 400, 10);
    if (!st) return null;
    var T = st.T;

    var STATIONS = [
      { at: [0, 0, 0], role: "ink", label: "read the inbox" },
      { at: [9, 2.5, -15], role: "hot", label: "muffle the hidden text" },
      { at: [-8, -2, -31], role: "ink", label: "trace every target" },
      { at: [4, 1.5, -47], role: "gold", label: "write the log" },
    ];

    STATIONS.forEach(function (s) {
      var mat = paint(new T.MeshStandardMaterial({ roughness: 0.55, transparent: true, opacity: 0.9 }), s.role);
      s.mesh = new T.Mesh(new T.BoxGeometry(5.2, 3.2, 0.4), mat);
      s.mesh.position.set(s.at[0], s.at[1], s.at[2]);
      st.scene.add(s.mesh);
    });

    var curve = new T.CatmullRomCurve3(STATIONS.map(function (s) {
      return new T.Vector3(s.at[0], s.at[1], s.at[2] + 7);
    }));
    st.scene.add(new T.Line(
      new T.BufferGeometry().setFromPoints(curve.getPoints(100)),
      paint(new T.LineBasicMaterial({ transparent: true, opacity: 0.45 }), "faint")
    ));

    var progress = 0, target = 0, shown = -1;
    var last = STATIONS.length - 1;
    st.frame = function () {
      progress += (target - progress) * 0.08;      // ease toward the scroll
      var k = Math.min(0.999, Math.max(0, progress));
      st.camera.position.copy(curve.getPointAt(k));
      var ahead = curve.getPointAt(Math.min(0.999, k + 0.07));
      st.camera.lookAt(ahead.x, ahead.y, ahead.z - 7);

      STATIONS.forEach(function (s, i) {
        var near = 1 - Math.min(1, Math.abs(k - i / last) * 3.0);
        s.mesh.material.opacity = 0.28 + near * 0.66;
        s.mesh.rotation.y = Math.sin(progress * 5 + i) * 0.2;
      });
      var at = Math.round(k * last);
      if (labelEl && at !== shown) {
        shown = at;
        labelEl.textContent = STATIONS[at].label;
      }
    };

    return { setProgress: function (p) { target = p; }, stations: STATIONS.length };
  }

  global.MG_3D = { chain: chain, graph: graph, flight: flight, available: !REDUCED };
})(window);
