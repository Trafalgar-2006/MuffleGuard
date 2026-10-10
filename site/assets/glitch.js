/* The refusal, rejected at the rendering level.
 *
 * One burst, about 150ms, on the frame the policy engine blocks the call: the
 * panel separates into colour channels and a few horizontal bands slip out of
 * register, the way a frame does when the data behind it is malformed.
 *
 * It fires exactly once per run and only on the block. Restraint is the whole
 * point: a page that glitches continuously is decoration, and a security tool
 * that looks unstable is not reassuring. This is the one moment where the
 * system is visibly refusing something, so it is the one moment that is
 * allowed to look violent.
 *
 * This is a DOM compositing effect, not a post-processing shader pass. It
 * channel-shifts and displaces for real, but there is no GPU pipeline behind
 * it, and it is described that way rather than dressed up.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var BANDS = 7;

  function rand(a, b) { return a + Math.random() * (b - a); }

  /* Two tinted copies of the panel, offset in opposite directions, plus a few
   * bands clipped out of each so the displacement is per-slice rather than a
   * flat double-vision. */
  function layer(el, tint, blend) {
    var c = el.cloneNode(true);
    c.setAttribute("aria-hidden", "true");
    c.removeAttribute("data-refusal");
    // Nothing inside a clone should be reachable or announced twice.
    Array.prototype.forEach.call(c.querySelectorAll("a,button,input"), function (n) {
      n.setAttribute("tabindex", "-1");
    });
    c.style.cssText +=
      ";position:absolute;left:0;top:0;width:100%;height:100%;pointer-events:none;" +
      "mix-blend-mode:" + blend + ";opacity:.85;will-change:transform,clip-path;";
    var sheet = document.createElement("div");
    sheet.style.cssText =
      "position:absolute;inset:0;background:" + tint + ";mix-blend-mode:multiply;pointer-events:none";
    c.appendChild(sheet);
    return c;
  }

  function burst(el, ms) {
    if (!el || REDUCED || el.__glitching) return;
    el.__glitching = true;
    ms = ms || 150;

    var host = el;
    var prevPosition = host.style.position;
    if (getComputedStyle(host).position === "static") host.style.position = "relative";

    var red = layer(host, "#ff2d16", "screen");
    var cyan = layer(host, "#16e0ff", "screen");
    host.appendChild(red);
    host.appendChild(cyan);

    var started = 0;
    function frame(t) {
      if (!started) started = t;
      var k = (t - started) / ms;
      if (k >= 1) {
        red.remove();
        cyan.remove();
        host.style.position = prevPosition;
        host.__glitching = false;
        return;
      }

      // Displacement decays across the burst, so it lands hard and settles.
      var power = (1 - k) * (1 - k);
      var shift = rand(-7, 7) * power;
      red.style.transform = "translate3d(" + shift + "px,0,0)";
      cyan.style.transform = "translate3d(" + (-shift) + "px,0,0)";

      // A handful of bands slip; the rest hold. Re-cut every frame so the
      // tear moves rather than sitting in one place.
      var cuts = [];
      for (var i = 0; i < BANDS; i++) {
        var top = (i / BANDS) * 100;
        var h = 100 / BANDS;
        cuts.push(
          Math.random() < 0.45
            ? "inset(" + top + "% 0 " + (100 - top - h) + "% 0)"
            : null
        );
      }
      var pick = cuts.filter(Boolean)[0];
      if (pick) { red.style.clipPath = pick; }
      var pick2 = cuts.filter(Boolean)[1];
      if (pick2) { cyan.style.clipPath = pick2; }

      // The host is deliberately left alone: its entrance tween owns
      // transform, and two writers on one property is how an animation ends
      // up fighting itself. The tear comes from the layers.
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  global.MG_GLITCH = { burst: burst, available: !REDUCED };
})(window);
