/* Motion for the MuffleGuard site.

   Fifteen animations, and each one is meant to carry the argument rather than
   decorate it: the headline arrives a line at a time because the sentence turns
   at the third line, the hidden instruction fades in because that is literally
   what the model sees and you do not, the counters count because the numbers
   are the claim.

   Everything lives inside gsap.matchMedia. Someone who asks for reduced motion
   gets the finished page immediately, with no element left mid-animation. */

(function () {
  "use strict";

  if (!window.gsap) return;               // no library, no hidden content
  document.documentElement.classList.add("js");
  gsap.registerPlugin(ScrollTrigger);

  const mm = gsap.matchMedia();
  const RISE = "[data-rise]";

  /* ---------------- reduced motion: show everything, animate nothing -------- */

  mm.add("(prefers-reduced-motion: reduce)", () => {
    gsap.set([RISE, ".hero h1 .line > span"], { opacity: 1, y: 0 });
    gsap.set("#mailHidden", { opacity: 1, y: 0 });
    gsap.set(".term .l", { opacity: 1 });
    gsap.set(".tri-hot, .tri-hot-t", { opacity: 1 });
    gsap.set(".invariant .q .w", { opacity: 1 });
    document.getElementById("mailTag")?.removeAttribute("hidden");
    document.querySelectorAll("[data-count]").forEach((el) => {
      el.textContent = el.dataset.count + (el.dataset.suffix || "");
    });
    document.querySelectorAll("[data-bar]").forEach((el) => {
      el.style.width = el.dataset.bar + "%";
    });
    document.querySelectorAll(".mech__step").forEach((s) => s.classList.add("is-on"));
  });

  /* ---------------- full motion -------------------------------------------- */

  mm.add("(prefers-reduced-motion: no-preference)", () => {
    /* 1. The monogram draws itself, then the wordmark arrives. The logo is the
          first thing anyone judges, so it is the first thing that moves. */
    const strokes = document.querySelectorAll(".mg-m, .mg-g");
    strokes.forEach((p) => {
      const len = p.getTotalLength();
      gsap.set(p, { strokeDasharray: len, strokeDashoffset: len });
    });
    const intro = gsap.timeline();
    intro
      .to(strokes, { strokeDashoffset: 0, duration: 0.85, ease: "power2.inOut", stagger: 0.12 })
      .from(".mg-bar", { scaleX: 0, transformOrigin: "left center", duration: 0.3, ease: "power2.out" }, "-=0.25")
      .from(".mg-word", { opacity: 0, x: -8, duration: 0.45, ease: "power2.out" }, "-=0.2");

    /* 2. The headline, one line at a time, each clipped by its own mask so the
          words slide out from behind the line above. */
    intro.from(
      ".hero h1 .line > span",
      { yPercent: 115, duration: 0.8, ease: "power3.out", stagger: 0.09 },
      "-=0.45"
    );

    /* 3. Everything else in the hero follows the headline. */
    intro.to(
      ".hero [data-rise]",
      { opacity: 1, y: 0, duration: 0.6, ease: "power2.out", stagger: 0.08 },
      "-=0.5"
    );
    gsap.set(".hero [data-rise]", { y: 14 });

    /* 4. The hidden instruction. It appears after the mail has been read for a
          beat, which is the point being made: you read the top, the model read
          all of it. */
    const hidden = document.getElementById("mailHidden");
    if (hidden) {
      intro.to(hidden, { opacity: 1, y: 0, duration: 0.5, ease: "power2.out" }, "+=0.5")
           .set("#mailTag", { attr: { hidden: null } })
           .from("#mailTag", { opacity: 0, duration: 0.3 });
    }

    /* 5. The counters. They run once, when the row is actually on screen. */
    document.querySelectorAll("[data-count]").forEach((el) => {
      const target = Number(el.dataset.count);
      const suffix = el.dataset.suffix || "";
      const n = { v: 0 };
      gsap.to(n, {
        v: target,
        duration: 1.1,
        ease: "power2.out",
        scrollTrigger: { trigger: el, start: "top 88%", once: true },
        onUpdate: () => { el.textContent = Math.round(n.v) + suffix; },
      });
    });

    /* 6. Section furniture rises as it arrives, batched so a row of three
          staggers together instead of three times separately. */
    gsap.set(".band " + RISE + ", .foot " + RISE, { y: 18 });
    ScrollTrigger.batch(".band " + RISE, {
      start: "top 86%",
      once: true,
      onEnter: (els) => gsap.to(els, { opacity: 1, y: 0, duration: 0.6, ease: "power2.out", stagger: 0.08 }),
    });

    /* 7. The trifecta circles draw in order, then the overlap lights up: the
          diagram makes its own argument in sequence. */
    const tri = document.getElementById("trifecta");
    if (tri) {
      const circles = tri.querySelectorAll(".tri-c");
      circles.forEach((c) => {
        const len = c.getTotalLength();
        gsap.set(c, { strokeDasharray: len, strokeDashoffset: len });
      });
      gsap.timeline({ scrollTrigger: { trigger: tri, start: "top 72%", once: true } })
        .to(circles, { strokeDashoffset: 0, duration: 0.9, ease: "power2.inOut", stagger: 0.18 })
        .from(tri.querySelectorAll(".tri-t"), { opacity: 0, duration: 0.4, stagger: 0.06 }, "-=0.5")
        .to(".tri-hot", { opacity: 1, duration: 0.4, ease: "back.out(2)" }, "-=0.1")
        .to(".tri-hot-t", { opacity: 1, duration: 0.3 }, "-=0.2");
    }

    /* 8. The marquee. Half the row is a duplicate, so resetting at -50% loops
          without a seam. */
    const row = document.getElementById("marquee");
    if (row) {
      row.innerHTML += row.innerHTML;
      gsap.to(row, { xPercent: -50, duration: 28, ease: "none", repeat: -1 });
    }

    /* 9 and 10. The mechanism diagram: boxes settle, then the wires between
          them draw towards the guard. */
    const fig = document.getElementById("mechFigure");
    if (fig) {
      gsap.timeline({ scrollTrigger: { trigger: fig, start: "top 75%", once: true } })
        .from(fig.querySelectorAll(".m-box"), { opacity: 0, scale: 0.94, transformOrigin: "center", duration: 0.5, ease: "power2.out", stagger: 0.08 })
        .from(fig.querySelector(".m-core"), { opacity: 0, scaleY: 0.6, transformOrigin: "center", duration: 0.5, ease: "back.out(1.6)" }, "-=0.2")
        .from(fig.querySelectorAll(".m-wire"), { drawSVG: 0, opacity: 0, duration: 0.4, stagger: 0.07 }, "-=0.25");
    }

    /* 11. The three layers highlight one at a time while the diagram stays put.
           Pinning only makes sense where there is room for it. */
    mm.add("(min-width: 981px)", () => {
      const steps = gsap.utils.toArray(".mech__step");
      if (!steps.length) return;
      /* The figure holds its place with CSS position:sticky rather than a
         ScrollTrigger pin. A pin rewrites the height of the page, which left
         every trigger below it measuring against the old layout and whole
         sections invisible. Sticky costs nothing and cannot do that. */
      steps.forEach((step) => {
        ScrollTrigger.create({
          trigger: step,
          start: "top 62%",
          end: "bottom 42%",
          onToggle: (self) => step.classList.toggle("is-on", self.isActive),
        });
      });
    });

    /* 12. The invariant, read word by word as you scroll through it. The
           sentence is the product's one promise, so it is worth slowing down. */
    const q = document.getElementById("invariant");
    if (q) {
      const words = q.textContent.trim().split(/\s+/);
      q.textContent = "";
      words.forEach((w, i) => {
        const s = document.createElement("span");
        s.className = "w";
        s.textContent = w;
        q.appendChild(s);
        // The gap goes between the spans, not inside them: a trailing space
        // within an inline-block collapses and the sentence runs together.
        if (i < words.length - 1) q.appendChild(document.createTextNode(" "));
      });
      gsap.fromTo(
        q.querySelectorAll(".w"),
        { opacity: 0.22 },
        {
          opacity: 1,
          ease: "none",
          stagger: 0.5,
          scrollTrigger: { trigger: q, start: "top 78%", end: "bottom 55%", scrub: 0.4 },
        }
      );
    }

    /* 13. The terminal prints a line at a time, the way it would have. */
    const term = document.getElementById("term");
    if (term) {
      gsap.to(term.querySelectorAll(".l"), {
        opacity: 1,
        duration: 0.08,
        stagger: 0.14,
        ease: "none",
        scrollTrigger: { trigger: term, start: "top 76%", once: true },
      });
    }

    /* 14. Scorecard rows, then the bars that make 100 and 0 visible as lengths
           rather than as digits. */
    ScrollTrigger.batch(".score tbody tr", {
      start: "top 88%",
      once: true,
      onEnter: (rows) => gsap.from(rows, { opacity: 0, y: 14, duration: 0.5, ease: "power2.out", stagger: 0.1 }),
    });
    document.querySelectorAll("[data-bar]").forEach((bar) => {
      gsap.to(bar, {
        width: bar.dataset.bar + "%",
        duration: 0.9,
        ease: "power2.out",
        scrollTrigger: { trigger: bar, start: "top 92%", once: true },
      });
    });

    /* 15. Hover physics. Buttons and steps answer the pointer, so the page
           feels built rather than printed. */
    document.querySelectorAll(".btn").forEach((b) => {
      b.addEventListener("mouseenter", () => gsap.to(b, { y: -2, duration: 0.2, ease: "power2.out" }));
      b.addEventListener("mouseleave", () => gsap.to(b, { y: 0, duration: 0.25, ease: "power2.out" }));
    });
    document.querySelectorAll(".mech__step").forEach((s) => {
      s.addEventListener("mouseenter", () => gsap.to(s, { x: 5, duration: 0.25, ease: "power2.out" }));
      s.addEventListener("mouseleave", () => gsap.to(s, { x: 0, duration: 0.3, ease: "power2.out" }));
    });

    /* The pin above changes the height of the page, which leaves every trigger
       created before it measuring against the old layout: everything below the
       pinned section stayed invisible until this refresh was added. */
    ScrollTrigger.refresh();
  });


  /* Safety net.

     A reveal that never fires leaves a blank section, which is far worse than
     a missed animation. Fast scrolling, an anchor jump and a restored scroll
     position can all outrun a batched trigger, so anything the reader has
     already reached is shown regardless of whether its trigger fired.

     Runs on a debounce after scrolling stops, so it never competes with the
     animation it is backing up. */
  let idle;
  const rescue = () => {
    const limit = window.scrollY + window.innerHeight;
    document.querySelectorAll("[data-rise]").forEach((el) => {
      if (getComputedStyle(el).opacity !== "0") return;
      if (el.getBoundingClientRect().top + window.scrollY < limit) {
        gsap.to(el, { opacity: 1, y: 0, duration: 0.35, overwrite: "auto" });
      }
    });
  };
  addEventListener("scroll", () => { clearTimeout(idle); idle = setTimeout(rescue, 220); }, { passive: true });
  addEventListener("load", () => setTimeout(rescue, 1400));

  /* Web fonts change every measurement on the page, so positions are recomputed
     once they have actually landed. The net runs again afterwards: a reader who
     arrived at an anchor deep in the page never scrolls, so nothing else would
     ever ask whether the content above them is visible. */
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(() => {
      ScrollTrigger.refresh();
      setTimeout(rescue, 200);
    });
  }
})();
