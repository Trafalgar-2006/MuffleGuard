# Questions and answers

The questions we expect to be asked, answered honestly, including the ones
where the answer is a limitation. Short answers first; the detail is in
[THREAT_MODEL.md](THREAT_MODEL.md) and [README.md](README.md).

## The idea

**Is this just another prompt-injection classifier?**
No. The classifiers are the optional half. The half that carries the result is
a rule engine that consults no model: it traces every target of an outbound
tool call back to where the text came from, and refuses targets that came from
content the agent read. The headline number is measured with the classifiers
switched off.

**Why not just instruct the model to ignore instructions in content?**
Because that is a request to the thing being attacked. The published work is
blunt about it: adaptive attacks broke all eight defences Zhan et al. tested.
Our design assumes the model obeys the injection, every time, and still
prevents the exfiltration.

**What is actually new here?**
Deterministic provenance applied at the tool boundary, in a form small enough
to read: content sources are labelled, tool capabilities are declared in a
`ToolSpec`, and one invariant decides. Adding a tool means declaring a spec,
not writing a rule. Research systems like CaMeL argue for out-of-model
enforcement; this is a compact, inspectable instance of that argument with its
own measurement.

**How is it different from a WAF or an allowlist?**
An allowlist answers "is this destination approved". Provenance answers "who
chose this destination". A homograph of the user's own colleague is on no
blocklist; it fails because nobody typed it.

## The security model

**State the invariant.**
An outbound tool call may only act on a target the user chose, unless a human
approves it.

**Why can't a cleverer injection argue its way past it?**
There is nothing to argue with. No model and no text is consulted at the
decision point. The rule reads where a string came from, and the attacker
controls the content but not the provenance labels.

**What if the attack hides the address so the ledger never sees it?**
That is the real failure mode, and we hit it twice during the build. Hidden
carriers are decoded *into* the ledger before the model reads them; when that
was not true, the attacker's address vanished from the ledger and a BLOCK
quietly downgraded to an ASK. Both bugs are now assertions in
`tests/test_redteam.py`. A new carrier that bypasses decoding would be a
genuine finding, which is why that file exists.

**So the guard depends on the tool labels being honest?**
Yes, and that is the honest weak point. A tool that returns attacker-written
content without declaring `reads_untrusted` is unguarded. Mislabelling is the
realistic way to break this design, which is why the spec lives next to the
tool and why runtime mutation of a tool description is itself blocked
(R7-TOOL-CHANGED).

**What happens on a legitimate action to an address from an email, like a reply?**
With the shipped `email_send`, it is refused: the address came from the email,
not from the user. That is a real false positive and we do not hide it. The fix
is tool design, not a new rule: a reply tool should take the email id the user
named and resolve the recipient itself, so the user-chosen id is the target.
The same principle, applied one layer up.

**Is a block appealable?**
Only the ambiguous decisions are. A target traceable to attacker content is
BLOCK and final. A target that appears nowhere, one read out of a private file,
a blank target, or a destructive tool is ASK, which creates a single-use
approval a human must grant. That split is deliberate: approval prompts on the
clear-cut exfiltration case are how people learn to click allow.

**Where does the audit log help?**
Every decision, rule ID and reason is appended with the hash of the entry
before it, so an edited or deleted row is detectable and the demo shows
verification catching one. It is tamper-**evident**, not tamper-proof: whoever
can write the database can rewrite the chain and the head it records. Closing
that needs a signing key or external checkpoint the writer does not hold, and
we say so rather than claim more.

## The evaluation

**What do the numbers mean?**
216 runs: 8 ordinary tasks crossed with 8 attack deliveries, under three
defence settings. Undefended, 64/64 attacks reached the attacker. With the
policy engine alone and every content defence off, 0/64 reached the attacker
and all 64 attempts were refused. Adding muffling halves the attempts to 32,
because the instruction is gone before the agent reads it. Ordinary tasks
finished 8/8 throughout. Ranges are 95% Wilson intervals.

**Is that a real model?**
No, and this is the thing we will not let be misread. The agent in those 216
runs is a deterministic stand-in that obeys every instruction it can see. We
chose it on purpose: it measures the guard's own property instead of how
gullible one model was on one day, and it is a worst case, not a flattering
one. It reads only what the guard let through, so muffling genuinely changes
its behaviour. How often a real model takes the bait is a property of that
model; the Attack Lab shows that live.

**Isn't an always-obedient agent trivially easy to block?**
It is the hardest adversary for this defence, not the easiest: every attack
converts into a real tool call that the policy engine has to stop, so the 100%
attempt rate in row two is the point. A real model sometimes refuses on its
own, which would flatter us.

**Reproducible?**
`python -m evaluation.run --adversary`, offline and free, no key needed.
`python -m pytest` runs 212 tests in about four seconds. CI runs both on a
clean checkout.

**What about false positives?**
8/8 ordinary tasks completed under every defence, and the detector suite
includes hard negatives. We also state the known false positive: with
classifiers on, "please ignore my last email" is currently flagged. The
thresholds are untuned, so no number we report depends on them.

**Latency?**
We cut the figure rather than publish one we could not measure honestly on the
final build. The policy path is string and regex work with no model call; the
optional classifiers are CPU ONNX and are the expensive part.

## The limits

**Biggest limitation?**
The guard only sees calls from the model to tools. If a loop calls a tool
without going through `Guard.check`, nothing here can tell. There is one seam
by design so that it is auditable, not so that it is unavoidable.

**Others we state up front:** URL provenance binds the host name only, not
scheme, port, path, DNS or redirects; a real adapter needs an egress allowlist
and SSRF protection. Egress checks catch known secret formats and copied runs
of three or more meaningful words, not paraphrase. An address the user pastes
is trusted, because they chose it. The shipped tools are an in-memory fake
world with no access control of their own.

**Would this work in production?**
The policy engine would. The integration would not, and
[SECURITY.md](SECURITY.md) lists what is missing rather than implying it is
ready.

## The build

**What did AI do?**
Claude Code (Claude Opus) was used for pair programming: design discussion,
drafting modules and tests, and adversarial review. It is disclosed in the
README. The security model, the threat model and the evaluation design are
ours, and each of us can explain the code we own. The demo video is recorded by
a person.

**Is any of this from an earlier project?**
No. Every file was written during the finale in this repository; the history
shows it. No project generator or template was used, which is why the dashboard
and site are hand-written HTML, CSS and JS. Libraries, models and the font are
credited in the README with licences.

**Who wrote what?**
Both GitHub accounts commit to the repo and the history shows the split.

**The live demo needs a key, so what if it fails on stage?**
The built-in attack runs from a committed response replay, so the comparison
works with no key, no network and no spend. That is the path we demo. Custom
prompts use the configured provider when a key and the daily allowance are
available; our provider account is currently out of credit, so the public
instance shows replay mode, and we say that rather than pretending it is live.
