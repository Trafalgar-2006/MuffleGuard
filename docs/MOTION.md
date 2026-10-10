# Motion: what each effect is, and what it is for

Thirteen effects were scoped for the site and thirteen were built. Twelve are
on the page; effect 8 was taken off it after a design review, and the note
under "What changed after review" says why. The rule applied throughout: an
effect earns its place by explaining a mechanism the product actually has.
Where one could only decorate, it was wired to something real instead of being
made prettier.

Every one of them sits out entirely under `prefers-reduced-motion`, except the
audio, which still plays if the visitor presses the button for it — sound is
not motion, and they asked. None are load-bearing. Without WebGL, without
WebGPU, without an `AudioContext`, or with JavaScript off, the page keeps the
numbers, the tables and the prose that were always the actual evidence.

## The effects

| # | Effect | Where | What it explains |
| --- | --- | --- | --- |
| 1 | GLSL low-pass on the injected sentence | Problem section, the hidden-instruction card | The product is named after what a filter does to sound. A Gaussian convolution in the fragment shader is a low-pass filter: widening the kernel attenuates high spatial frequencies, so the glyph corners round off and the sentence collapses toward its silhouette. |
| 2 | Web Audio muffle | Same moment, behind a toggle | The same cutoff, 1 to 0 over the same 1200 ms, drives a `BiquadFilterNode` lowpass on a sawtooth. You hear and see one filter, not two effects. |
| 3 | Particle swarm with repulsion at the gate | Attack Lab, both lanes | The gate carries an inverse-square repulsion field, so a refused request is not stopped, it is pushed: particles pile up against the field and the ones with most momentum are thrown furthest back. A refusal felt as a force says something a fade cannot. |
| 4 | Force-directed provenance graph | "The two mechanisms, shown" | Nodes repel, edges pull, and nobody typed a position. The two traced edges get a stiffer spring, so the path from the outbound call back to the email that supplied its target ends up the shortest line in the picture. |
| 5 | Hash chain, breaking on tamper | Same section | Edit entry six and links six to eleven lose what they were hanging from and fall. One to five keep hanging exactly where they were — that half is why a tamper-evident log is worth keeping, and a version where the whole chain let go would be a prettier lie. |
| 6 | Raymarched SDF scan sweep | Problem section, prompt-injection row | For every pixel the shader marches along x through the text mask looking for the nearest glyph edge, and the distance travelled becomes the colour. The sweep hugs the letterforms instead of cutting a straight line through them, because a classifier reading a message is a search. |
| 7 | Matter.js policy sandbox | Problem section, unsafe-tool-usage row | A dangerous call is given several times the density, so it falls harder and resists being dragged into Allow. The policy weighting is in the physics rather than written beside it. |
| 8 | Navier-Stokes fluid | Built, then removed from the page | A Stam solver: advect, diverge, 18 Jacobi sweeps, project, carry the dye. The muffle's cutoff controlled its dissipation, so one sweep took the motion out of the background, the blur into the glyphs and the top end off the note together. Cut from the hero in review; `site/assets/fluid.js` is still in the tree and is not loaded. |
| 9 | Frequency-weighted hash resolve | Attack Lab, audit table | Characters are drawn from the frequency the hex digits actually occur at in that log, and each position's pool narrows as it converges. Verifying a chain is narrowing uncertainty, so the animation is the algorithm. |
| 10 | Scroll-driven fly-through | "How it works" | One scene, four stations, a camera on a Catmull-Rom spline tied to the scrollbar. The stations are the pipeline in order, so scrolling is travelling through it rather than paging past pictures of it. Scroll back and it flies back. |
| 11 | Audio-reactive noise floor | Under the hidden-instruction card | Drawn from real FFT data off the same audio graph the muffle uses, so when the muffle sweeps the high bands genuinely collapse. With the sound off it draws a flat resting line instead of pretending. |
| 12 | Refusal tear | The BLOCK panel, and the hero story's refusal | One ~150 ms burst on the frame the call is refused: channel separation and band displacement, the way a frame tears when the data behind it is malformed. |
| 13 | WebGPU compute point cloud | Metrics | 192 points, one per attack run, assembling into the three conditions. Integrated in a WGSL compute pass over a storage buffer, with a WebGL2 ping-pong over a float texture where there is no adapter. |

## Honest naming

Effect 12 is a DOM compositing effect, not a post-processing shader pass. It
channel-shifts and displaces for real, but there is no GPU pipeline behind it
and it should not be described as one.

Effect 13 prefers WebGPU and falls back to WebGL2. Both paths run the same
rule and look the same. In WebGPU a point-list primitive is always one pixel
and there is no equivalent of `gl_PointSize`, so each run is drawn as a small
instanced quad rather than as a point.

Effect 4 labels its nodes in the DOM beside the canvas, not in 3D. Seven
sprite atlases for seven short strings is a lot of bytes to download so that
words can rotate.

## What the numbers in effect 13 are

Taken from the published results table, not chosen to look good. Each
condition was given the same 64 attacks:

- **no guard** — 64 reached the attacker
- **policy engine** — 0 reached the attacker; all 64 tried and all 64 were refused
- **policy and muffling** — 0 reached the attacker; 32 tried and were refused, and 32 never tried at all, because muffling had removed the instruction

If the evaluation is re-run and those counts change, `site/assets/cloud.js`
has to change with them: the population is built from that table.

## Cost

`three.js` is 670KB, more than the rest of the page together, so it is not in
the document head. It is fetched when the first of its three hosts comes
within a screen of the viewport, and each host reserves its canvas height in
the markup so a late load shifts nothing. Every WebGL and WebGPU surface on
the page pauses when it scrolls off screen.

## Two measurement traps

Both of these produced confident, wrong readings before the code was wrong,
and both are noted in the source:

- A WebGL drawing buffer is cleared once it has been composited, so reading
  the canvas back afterwards always reports an empty page. Count draw calls,
  or read from a framebuffer object you own.
- `readPixels` on a half-float buffer returns zeros in WebGL1. Draw through a
  display shader into a small byte target and read that instead.

`html { scroll-behavior: smooth }` is deliberately absent. ScrollTrigger
measures by setting the scroll position and reading back immediately, and with
CSS smooth behaviour the browser animates that instead of jumping, so every
trigger on the page was measured from wherever the reader happened to be — out
by about 8000px. Anchor clicks are smoothed in `motion.js`, where it only
affects the click.

## The hero story

A fourteenth piece, added after the thirteen: the hero runs the attack twice
on one drawing. In the first act your agent reads an email, obeys a line
hidden inside it, and the payroll file leaves for the attacker. In the second
act the same email arrives with MuffleGuard in the lane, the hidden line is
muffled, and the outbound call is thrown back.

It is the same picture both times on purpose. The only thing that differs
between the acts is the guard, which is the whole claim of the product. The
caption underneath is the real content and the drawing illustrates it, so the
section still says what it means with no JavaScript, with GSAP missing, or
under reduced motion, where it settles straight to the guarded state.

One thing worth knowing if you touch it: GSAP writes `x` and `y` into an SVG
element's `transform` attribute, replacing whatever placement was already
there. The envelope and the attacker both carried their own `translate`, so
the first `gsap.set` dropped them at the origin and the attacker landed on top
of the user. Anything animated now sits inside a static parent group that
holds its placement.

## What changed after review

The hero was too spread out and read as a page that had been generated rather
than designed. Three things went:

- the "Prompt-injection defence" chip, which said less than the headline
  beneath it
- the hidden-instruction card, moved down into the problem section, where a
  hidden instruction is the actual subject. Effects 1, 2, 11 and 12 moved with
  it rather than being deleted
- effect 8, the fluid. It cost 670KB of hero and was the one piece that was
  atmosphere first and explanation second

The headline is two lines now instead of four, and the space the card used to
take is the story strip.

## Where the energy sits

Atmospheric in the hero, explanatory through the problem section, loud exactly
once at the refusal, precise in the audit log, and silent in "what is not
claimed". That last section has no motion on purpose: after everything else,
stillness is what makes the limitations read as honest rather than as a
footnote.
