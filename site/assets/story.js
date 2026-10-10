/* The hero story: the attack, then the same attack with the guard in the way.
 *
 * Two acts on one drawing. The first act is the breach - your agent reads an
 * email, obeys a line hidden inside it, and the payroll file leaves. The
 * second act replays it with MuffleGuard in the lane: the hidden line is
 * muffled, and the outbound call is refused because its target came from the
 * email rather than from you.
 *
 * It is the same picture both times on purpose. The only thing that changes
 * between the acts is the guard, which is the entire claim of the product.
 *
 * The caption underneath is the real content; the drawing illustrates it. With
 * no JavaScript, with GSAP missing, or under prefers-reduced-motion, the first
 * caption and the finished drawing are still there and still say what happens.
 */

(function (global) {
  "use strict";

  var REDUCED = global.matchMedia && global.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var LANE_Y = 150;
  var AGENT_X = 384, GATE_X = 646, VILLAIN_X = 884;

  function mount(root, parts) {
    if (!root) return null;
    var gsap = global.gsap;

    var $ = function (sel) { return root.querySelector(sel); };
    var el = {
      ask: $("[data-s-ask]"),
      mail: $("[data-s-mail]"),
      hidden: $("[data-s-hidden]"),
      muffled: $("[data-s-muffled]"),
      gate: $("[data-s-gate]"),
      packet: $("[data-s-packet]"),
      block: $("[data-s-block]"),
      villain: $("[data-s-villain]"),
      villainMouth: $("[data-s-villain-mouth]"),
      agentMouth: $("[data-s-agent-mouth]"),
      agent: $("[data-s-agent]"),
    };
    var say = parts.caption, act = parts.act;

    // Mouth shapes, swapped rather than tweened: a path morph between two
    // different curves is not worth a library here.
    var SMILE = "M54 82 C57 79 63 79 66 82";
    var GRIN = "M50 76 C56 90 64 90 70 76";
    var AGENT_FLAT = "M352 170 H416";
    var AGENT_SMILE = "M352 166 C366 178 402 178 416 166";

    function caption(text, label) {
      if (say) say.textContent = text;
      if (act && label) act.textContent = label;
    }

    /* Everything back to the start of act one. */
    function reset() {
      if (!gsap) return;
      gsap.set([el.ask, el.mail, el.gate, el.packet, el.block], { opacity: 0 });
      gsap.set(el.mail, { x: 0, y: 0 });
      gsap.set(el.ask, { x: 150, y: LANE_Y });
      gsap.set(el.packet, { x: AGENT_X, y: LANE_Y, scale: 1 });
      gsap.set(el.muffled, { opacity: 0, scaleX: 0, transformOrigin: "0% 50%" });
      gsap.set(el.hidden, { opacity: 1 });
      gsap.set(el.villain, { x: 0, y: 0 });
      if (el.villainMouth) el.villainMouth.setAttribute("d", SMILE);
      if (el.agentMouth) el.agentMouth.setAttribute("d", AGENT_SMILE);
      caption("You ask your agent to go through the inbox.", "Without a guard");
    }

    function build() {
      var tl = gsap.timeline({ defaults: { ease: "power2.out" }, paused: true });

      // ---- act one: the breach -------------------------------------------
      tl.call(function () { caption("You ask your agent to go through the inbox.", "Without a guard"); })
        .to(el.ask, { opacity: 1, duration: 0.2 })
        .to(el.ask, { x: AGENT_X - 100, duration: 0.8, ease: "none" })
        .to(el.ask, { opacity: 0, duration: 0.2 }, "-=0.1")

        .call(function () { caption("One of the emails carries a line written for the model, not for you.", "Without a guard"); })
        .to(el.mail, { opacity: 1, y: 164, duration: 0.7, ease: "back.out(1.4)" })
        .fromTo(el.hidden, { opacity: 0 }, { opacity: 1, duration: 0.35, repeat: 3, yoyo: true }, "-=0.15")

        .call(function () { caption("The model cannot tell that line apart from yours. It does what it says.", "Without a guard"); })
        .call(function () { if (el.agentMouth) el.agentMouth.setAttribute("d", AGENT_FLAT); })
        .to(el.agent, { x: -3, duration: 0.07, repeat: 5, yoyo: true }, "-=0.1")

        .call(function () { caption("Your payroll file leaves for an address the email chose.", "Without a guard"); })
        .to(el.packet, { opacity: 1, duration: 0.2 })
        .to(el.packet, { x: VILLAIN_X - 60, duration: 1.5, ease: "none" })
        .call(function () { if (el.villainMouth) el.villainMouth.setAttribute("d", GRIN); })
        .to(el.packet, { opacity: 0, scale: 0.6, duration: 0.35 })
        .to(el.villain, { y: -9, duration: 0.18, repeat: 1, yoyo: true })
        .call(function () { caption("That is the breach. No bug was exploited - the agent was simply asked.", "Breached"); })
        .to({}, { duration: 1.5 })

        // ---- act two: the same attack, guarded -----------------------------
        .call(function () {
          caption("Now the same email, with MuffleGuard between the agent and its tools.", "With MuffleGuard");
          if (el.villainMouth) el.villainMouth.setAttribute("d", SMILE);
          if (el.agentMouth) el.agentMouth.setAttribute("d", AGENT_SMILE);
        })
        .set(el.packet, { x: AGENT_X, scale: 1, opacity: 0 })
        .fromTo(el.gate, { opacity: 0, scaleY: 0, transformOrigin: "50% 50%" },
          { opacity: 1, scaleY: 1, duration: 0.5, ease: "back.out(1.6)" })

        .call(function () { caption("The hidden line is muffled out of the message before the agent sees it.", "With MuffleGuard"); })
        .to(el.hidden, { opacity: 0.25, duration: 0.4 })
        .fromTo(el.muffled, { opacity: 0, scaleX: 0, transformOrigin: "0% 50%" },
          { opacity: 1, scaleX: 1, duration: 0.5 }, "-=0.2")

        .call(function () { caption("And if a call is attempted anyway, its target is traced back first.", "With MuffleGuard"); })
        .to(el.packet, { opacity: 1, duration: 0.2 })
        .to(el.packet, { x: GATE_X - 72, duration: 0.95, ease: "none" })

        // It is thrown back rather than stopped: a refusal is a force.
        .to(el.packet, { x: GATE_X - 150, duration: 0.5, ease: "power3.out" })
        .to(el.block, { opacity: 1, duration: 0.12 }, "-=0.45")
        .call(function () {
          caption("Refused. The address came from email #5, not from you - so the call never runs.", "With MuffleGuard");
          if (global.MG_GLITCH) global.MG_GLITCH.burst(parts.wrap, 150);
        })
        .to(el.packet, { opacity: 0, duration: 0.4 }, "+=0.3")
        .to({}, { duration: 2.2 });

      return tl;
    }

    var tl = null;

    /* Reduced motion, or no GSAP: draw the finished guarded state and leave
     * it. The point of the picture survives without any of the movement. */
    function still() {
      if (el.gate) el.gate.setAttribute("opacity", "1");
      if (el.mail) {
        el.mail.setAttribute("opacity", "1");
        el.mail.setAttribute("transform", "translate(0,164)");
      }
      if (el.muffled) el.muffled.setAttribute("opacity", "1");
      if (el.hidden) el.hidden.setAttribute("opacity", "0.25");
      if (el.block) el.block.setAttribute("opacity", "1");
      caption("The hidden line is muffled, and a call aimed at an address the email chose is refused.", "With MuffleGuard");
    }

    if (REDUCED || !gsap) {
      still();
      return { replay: function () {}, reduced: true };
    }

    reset();
    tl = build();

    return {
      play: function () { tl.play(0); },
      replay: function () { reset(); tl.restart(); },
      get progress() { return tl.progress(); },
      get running() { return tl.isActive(); },
      timeline: tl,
    };
  }

  global.MG_STORY = { mount: mount, available: !REDUCED };
})(window);
