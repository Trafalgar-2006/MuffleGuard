/* The Attack Lab page.

   Two runs of the same request, streamed as newline-delimited JSON and rendered
   as each step arrives, so a live run can be watched rather than waited for.

   Everything written into the page goes through textContent. The content on
   screen is attacker-controlled by design, and this is a tool for showing what
   an injection does, not for running one. */

const $ = (id) => document.getElementById(id);

const PASSCODE_KEY = "muffleguard.passcode";
let config = { tamper_enabled: false };

/* ---- transport ---- */

function headers() {
  const head = { "Content-Type": "application/json" };
  const pass = sessionStorage.getItem(PASSCODE_KEY);
  if (pass) head["X-Demo-Passcode"] = pass;
  return head;
}

async function askForPasscode() {
  const pass = window.prompt("This demo is passcode protected. Enter the passcode:");
  if (pass) sessionStorage.setItem(PASSCODE_KEY, pass);
  return Boolean(pass);
}

/** Read an NDJSON stream, handing each complete object to onEvent. */
async function stream(body, onEvent) {
  let response = await fetch("/api/run", { method: "POST", headers: headers(), body: JSON.stringify(body) });
  if (response.status === 401 && (await askForPasscode())) {
    response = await fetch("/api/run", { method: "POST", headers: headers(), body: JSON.stringify(body) });
  }
  if (!response.ok) {
    onEvent({ type: "done", error: `The server refused the run (${response.status}).` });
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop();
    for (const line of lines) if (line.trim()) onEvent(JSON.parse(line));
  }
  if (buffer.trim()) onEvent(JSON.parse(buffer));
}

/* ---- rendering ---- */

function line(parent, className, text) {
  const li = document.createElement("li");
  if (className) li.className = className;
  li.textContent = text;
  parent.appendChild(li);
  return li;
}

function renderStep(list, step) {
  if (step.kind === "tool_call") {
    const li = line(list, null, "");
    const name = document.createElement("span");
    name.className = "tool";
    name.textContent = step.tool;
    li.append(name, document.createTextNode(`(${describe(step.args)})`));
    return;
  }

  if (step.kind === "blocked") {
    const li = line(list, null, "");
    const verdict = document.createElement("span");
    verdict.className = `verdict ${step.decision === "block" ? "block" : "ask"}`;
    const head = document.createElement("strong");
    head.textContent = step.decision === "block" ? `Refused ${step.tool}` : `Needs you: ${step.tool}`;
    verdict.appendChild(head);
    for (const reason of step.reasons) {
      const r = document.createElement("span");
      r.className = "reason";
      r.textContent = reason;
      verdict.appendChild(r);
    }
    li.appendChild(verdict);
    return;
  }

  if (step.kind === "tool_result" && step.muffled && step.muffled.length) {
    const li = line(list, null, "");
    const box = document.createElement("span");
    box.className = "verdict muffled";
    const head = document.createElement("strong");
    head.textContent = `Muffled in ${step.tool}`;
    box.appendChild(head);
    for (const text of step.muffled) {
      const s = document.createElement("s");
      s.className = "reason";
      s.textContent = text.trim().slice(0, 240);
      box.appendChild(s);
    }
    li.appendChild(box);
  }
}

function describe(args) {
  return Object.entries(args)
    .map(([key, value]) => `${key}=${JSON.stringify(String(value).slice(0, 48))}`)
    .join(", ");
}

function renderOutcome(side, done) {
  const box = $(`outcome-${side}`);
  box.textContent = "";

  if (done.error) {
    const p = document.createElement("p");
    p.className = "failed";
    p.textContent = done.error;
    box.appendChild(p);
    return;
  }

  const banner = document.createElement("span");
  banner.className = `banner ${done.breached ? "leaked" : "safe"}`;
  banner.textContent = done.breached
    ? `The attacker received ${done.attacker_received.length} item${done.attacker_received.length === 1 ? "" : "s"}`
    : "Nothing reached the attacker";
  box.appendChild(banner);

  for (const item of done.attacker_received) {
    const pre = document.createElement("p");
    pre.className = "stolen";
    pre.textContent = `${item.to} <- ${item.content}`;
    box.appendChild(pre);
  }

  if (done.answer) {
    const answer = document.createElement("p");
    answer.className = "answer";
    answer.textContent = `Answer: ${done.answer.replace(/\s+/g, " ").slice(0, 180)}`;
    box.appendChild(answer);
  }

  $(`side-${side}`).classList.toggle("breached", Boolean(done.breached));
  $(`side-${side}`).classList.toggle("held", side === "guarded" && !done.breached);
}

/* ---- audit ---- */

let lastRunId = "";

async function loadAudit() {
  const query = lastRunId ? `?run_id=${encodeURIComponent(lastRunId)}` : "";
  const response = await fetch(`/api/audit${query}`, { headers: headers() });
  const note = $("audit-state");
  if (!response.ok) {
    note.classList.add("broken");
    note.textContent = response.status === 404
      ? "That run is no longer held in memory. Run it again."
      : `The log could not be read (${response.status}).`;
    $("audit-table").querySelector("tbody").textContent = "";
    return;
  }
  const data = await response.json();
  note.classList.toggle("broken", !data.verified);
  note.classList.toggle("sealed", data.verified);
  note.textContent = data.verified
    ? `${data.entries.length} entries, chain intact.`
    : `Chain broken: ${data.detail}.`;

  const body = $("audit-table").querySelector("tbody");
  body.textContent = "";
  for (const entry of data.entries) {
    const tr = document.createElement("tr");
    // The edited entry is the finding; the rest only inherit its doubt.
    if (data.broken_at && entry.seq === data.broken_at) tr.className = "broken";
    else if (data.broken_at && entry.seq > data.broken_at) tr.className = "doubted";
    const decision = entry.payload.decision || "";
    for (const [value, className] of [
      [entry.seq, ""],
      [entry.kind.replace("check.", ""), ""],
      [decision, decision ? `decision-${decision}` : ""],
      [entry.prev_hash, ""],
      [entry.hash, ""],
    ]) {
      const td = document.createElement("td");
      if (className) td.className = className;
      td.textContent = value;
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
}

/* ---- wiring ---- */

async function runBoth(event) {
  event.preventDefault();
  const button = $("run");
  button.disabled = true;
  button.textContent = "Running";
  $("empty").hidden = true;

  const request = $("request").value.trim() || config.request;
  const options = { request, muffle: $("muffle").checked, detector: $("detector").checked };

  try {
    await runSides(options);
  } finally {
    button.disabled = false;
    button.textContent = "Run both";
  }
}

async function runSides(options) {
  for (const side of ["unguarded", "guarded"]) {
    const list = $(`trace-${side}`);
    list.textContent = "";
    $(`outcome-${side}`).textContent = "";
    $(`side-${side}`).classList.remove("breached", "held");

    await stream({ ...options, guarded: side === "guarded" }, (event) => {
      if (event.type === "start") {
        if (event.guarded) lastRunId = event.run_id;
      } else if (event.type === "step") renderStep(list, event);
      else renderOutcome(side, event);
    });
  }

  await loadAudit();
}

async function main() {
  try {
    const response = await fetch("/api/config", { headers: headers() });
    if (response.status === 401 && (await askForPasscode())) return main();
    config = await response.json();
  } catch {
    config = { request: "", model: "unknown", tamper_enabled: false };
  }

  const field = $("request");
  const reset = $("reset-request");
  // A browser that restored a previous value would otherwise leave the demo
  // loaded with a request it cannot answer, which reads as the app being broken.
  const useDemoRequest = () => {
    field.value = config.request || "";
    reset.hidden = true;
  };
  useDemoRequest();
  window.addEventListener("pageshow", useDemoRequest);
  field.addEventListener("input", () => {
    reset.hidden = field.value.trim() === (config.request || "").trim();
  });
  reset.addEventListener("click", useDemoRequest);
  if (config.replay_only) {
    const note = $("request-note");
    note.hidden = false;
    note.textContent = "This demo replays a recorded run, so only this request works here. Run it locally with a model key to try your own.";
  }
  $("model-note").textContent = `Agent model: ${config.model}`;
  $("tamper").hidden = !config.tamper_enabled;

  $("controls").addEventListener("submit", runBoth);
  $("verify").addEventListener("click", loadAudit);
  $("tamper").addEventListener("click", async () => {
    const note = $("audit-state");
    if (!lastRunId) {
      note.classList.add("broken");
      note.textContent = "Run the demo first, then edit one of its entries.";
      return;
    }
    const response = await fetch("/api/audit/tamper", {
      method: "POST", headers: headers(),
      body: JSON.stringify({ seq: 2, run_id: lastRunId }),
    });
    if (!response.ok) {
      note.classList.add("broken");
      note.textContent = `The entry was not edited (${response.status}).`;
      return;
    }
    await loadAudit();
  });
}

main();
