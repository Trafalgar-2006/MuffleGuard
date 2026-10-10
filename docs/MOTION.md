# Motion: what is built, what is placed, what was cut

Thirteen effects were scoped for the site. Four are built and live. The other
nine have a home chosen and a reason they are not in the hackathon build.

The rule applied throughout: an effect earns its place by explaining a
mechanism the product actually has. Anything that only decorates was cut, and
anything that could not be finished to a standard we would defend was cut
rather than shipped half-working.

## Built

| # | Effect | Where | What it explains |
| --- | --- | --- | --- |
| 1 | GLSL low-pass on the injected sentence | Hero, the hidden-instruction card | The product is named after what a filter does to sound. A Gaussian convolution in the fragment shader is a low-pass filter: widening the kernel attenuates high spatial frequencies, so the glyph corners round off and the sentence collapses toward its silhouette. |
| 2 | Web Audio muffle | Same moment, behind a toggle | The same cutoff, 1 to 0 over the same 1200 ms, drives a `BiquadFilterNode` lowpass on a sawtooth. You hear and see one filter, not two effects. |
| 9 | Frequency-weighted hash resolve | Attack Lab, audit table | Characters are drawn from the frequency the hex digits actually occur at in that log, and each position's pool narrows as it converges. Verifying a chain is narrowing uncertainty, so the animation is the algorithm. |
| 12 | Refusal tear | Hero, the BLOCK panel | One ~150 ms burst on the frame the call is refused: channel separation and band displacement, the way a frame tears when the data behind it is malformed. |

All four sit out entirely under `prefers-reduced-motion`, except the audio,
which still plays if the visitor presses the button for it — sound is not
motion, and they asked.

None are load-bearing. Without WebGL, without an `AudioContext`, or with
JavaScript off, the page keeps the strike-through and the typed reveal it
already had.

### Honest naming

Effect 12 is a DOM compositing effect, not a post-processing shader pass.
It channel-shifts and displaces for real, but there is no GPU pipeline behind
it and it should not be described as one.

## Placed, not built

Each has a section chosen. The estimates are why they are not here.

| # | Effect | Home | Why not now |
| --- | --- | --- | --- |
| 3 | GPU particle swarm with repulsion at the gate | Attack Lab, both lanes | Instanced physics is a day's work to make smooth, and the lane contrast already reads without it. |
| 4 | 3D force-directed provenance graph | How it works, the provenance stop | The flat diagram already answers "who chose this target". A 3D graph is more impressive and no clearer. |
| 5 | Hash chain as 3D links, breaking on tamper | Audit log | The strongest of the nine: a chain that visibly unanchors downstream of an edit is mechanically correct. Needs a physics engine and a camera system. |
| 6 | Raymarched SDF scan sweep | Problem section, prompt-injection row | Closest to buildable. Cut for time after the four above landed. |
| 7 | Matter.js policy sandbox | Problem section, unsafe-tool-usage row | A toy that makes policy weighting tactile. Scope creep in a hackathon window. |
| 8 | Navier-Stokes fluid background | Hero | Multi-day. Also atmospheric rather than explanatory, so the first to go. |
| 10 | Continuous scroll fly-through | How it works, as one scene | Multi-day, and it would replace a diagram that currently explains itself in one glance. |
| 11 | Audio-reactive noise floor | Ambient | Depends on 8 and 2 running together; little meaning on its own. |
| 13 | WebGPU compute assembling the bars | Metrics | Bleeding edge, needs a WebGL2 GPGPU fallback, and the numbers are already the proof. |

## If the work continues

In value order: 5 (the chain break is the one metaphor that is mechanically
true), then 6, then 3. 8, 10 and 13 are portfolio pieces rather than
explanations, and should only follow if the rest is finished.

## Where the energy sits

Atmospheric in the hero, explanatory through the problem section, loud exactly
once at the refusal, precise in the audit log, and silent in "what is not
claimed". That last section has no motion on purpose: after everything else,
stillness is what makes the limitations read as honest rather than as a
footnote.
