# Motion: what each effect is, and what it is for

Thirteen effects were scoped for the site and thirteen are built. The rule
applied throughout: an effect earns its place by explaining a mechanism the
product actually has. Where one could only decorate, it was wired to something
real instead of being made prettier.

Every one of them sits out entirely under `prefers-reduced-motion`, except the
audio, which still plays if the visitor presses the button for it — sound is
not motion, and they asked. None are load-bearing. Without WebGL, without
WebGPU, without an `AudioContext`, or with JavaScript off, the page keeps the
numbers, the tables and the prose that were always the actual evidence.

## The effects

| # | Effect | Where | What it explains |
| --- | --- | --- | --- |
| 1 | GLSL low-pass on the injected sentence | Hero, the hidden-instruction card | The product is named after what a filter does to sound. A Gaussian convolution in the fragment shader is a low-pass filter: widening the kernel attenuates high spatial frequencies, so the glyph corners round off and the sentence collapses toward its silhouette. |
| 2 | Web Audio muffle | Same moment, behind a toggle | The same cutoff, 1 to 0 over the same 1200 ms, drives a `BiquadFilterNode` lowpass on a sawtooth. You hear and see one filter, not two effects. |
| 3 | Particle swarm with repulsion at the gate | Attack Lab, both lanes | The gate carries an inverse-square repulsion field, so a refused request is not stopped, it is pushed: particles pile up against the field and the ones with most momentum are thrown furthest back. A refusal felt as a force says something a fade cannot. |
| 4 | Force-directed provenance graph | "The two mechanisms, shown" | Nodes repel, edges pull, and nobody typed a position. The two traced edges get a stiffer spring, so the path from the outbound call back to the email that supplied its target ends up the shortest line in the picture. |
| 5 | Hash chain, breaking on tamper | Same section | Edit entry six and links six to eleven lose what they were hanging from and fall. One to five keep hanging exactly where they were — that half is why a tamper-evident log is worth keeping, and a version where the whole chain let go would be a prettier lie. |
| 6 | Raymarched SDF scan sweep | Problem section, prompt-injection row | For every pixel the shader marches along x through the text mask looking for the nearest glyph edge, and the distance travelled becomes the colour. The sweep hugs the letterforms instead of cutting a straight line through them, because a classifier reading a message is a search. |
| 7 | Matter.js policy sandbox | Problem section, unsafe-tool-usage row | A dangerous call is given several times the density, so it falls harder and resists being dragged into Allow. The policy weighting is in the physics rather than written beside it. |
| 8 | Navier-Stokes fluid | Hero background | A Stam solver: advect, diverge, 18 Jacobi sweeps, project, carry the dye. It is here for what drives it — the muffle's cutoff controls dissipation, so one sweep takes the motion out of the background, the blur into the glyphs and the top end off the note at the same time. |
| 9 | Frequency-weighted hash resolve | Attack Lab, audit table | Characters are drawn from the frequency the hex digits actually occur at in that log, and each position's pool narrows as it converges. Verifying a chain is narrowing uncertainty, so the animation is the algorithm. |
| 10 | Scroll-driven fly-through | "How it works" | One scene, four stations, a camera on a Catmull-Rom spline tied to the scrollbar. The stations are the pipeline in order, so scrolling is travelling through it rather than paging past pictures of it. Scroll back and it flies back. |
| 11 | Audio-reactive noise floor | Hero foot | Drawn from real FFT data off the same audio graph the muffle uses, so when the muffle sweeps the high bands genuinely collapse. With the sound off it draws a flat resting line instead of pretending. |
| 12 | Refusal tear | Hero, the BLOCK panel | One ~150 ms burst on the frame the call is refused: channel separation and band displacement, the way a frame tears when the data behind it is malformed. |
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

## Where the energy sits

Atmospheric in the hero, explanatory through the problem section, loud exactly
once at the refusal, precise in the audit log, and silent in "what is not
claimed". That last section has no motion on purpose: after everything else,
stillness is what makes the limitations read as honest rather than as a
footnote.
