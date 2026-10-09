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

async function askForPasscode(message = "") {
  const dialog = $("passcode-dialog");
  const form = $("passcode-form");
  const input = $("passcode-input");
  const error = $("passcode-error");
  input.value = "";
  error.textContent = message;
  error.hidden = !message;

  return new Promise((resolve) => {
    const close = () => {
      form.removeEventListener("submit", submit);
      $("passcode-cancel").removeEventListener("click", cancel);
      resolve(dialog.returnValue === "unlock");
    };
    const submit = (event) => {
      event.preventDefault();
      sessionStorage.setItem(PASSCODE_KEY, input.value);
      dialog.close("unlock");
    };
    const cancel = () => dialog.close("cancel");
    form.addEventListener("submit", submit);
    $("passcode-cancel").addEventListener("click", cancel);
    dialog.addEventListener("close", close, { once: true });
    dialog.showModal();
    input.focus();
  });
}

/** Read an NDJSON stream, handing each complete object to onEvent. */
async function stream(body, onEvent) {
  let response = await fetch("/api/run", { method: "POST", headers: headers(), body: JSON.stringify(body) });
  if (response.status === 401) {
    if (!(await askForPasscode())) {
      onEvent({ type: "done", error: "The demo passcode is required to run this comparison." });
      return false;
    }
    response = await fetch("/api/run", { method: "POST", headers: headers(), body: JSON.stringify(body) });
  }
  if (!response.ok) {
    let message = response.status === 401 ? "The passcode was not accepted." : `The server refused the run (${response.status}).`;
    try { message = (await response.json()).detail || message; } catch { /* keep generic */ }
    onEvent({ type: "done", error: message });
    return true;
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
  buffer += decoder.decode();
  if (buffer.trim()) onEvent(JSON.parse(buffer));
  return true;
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

/* ---- scorecard ---- */

function rateCell(rate, goodWhenLow) {
  const td = document.createElement("td");
  const good = goodWhenLow ? rate.value === 0 : rate.value === 1;
  if (rate.total) td.className = good ? "good" : goodWhenLow && rate.value > 0 ? "bad" : "";
  const value = document.createElement("strong");
  value.textContent = rate.total ? `${Math.round(rate.value * 100)}%` : "n/a";
  td.appendChild(value);
  if (rate.total) {
    const ci = document.createElement("span");
    ci.className = "ci";
    ci.textContent = ` ${rate.successes}/${rate.total}, ${Math.round(rate.low * 100)}-${Math.round(rate.high * 100)}%`;
    td.appendChild(ci);
  }
  return td;
}

const DEFENCE_NAMES = {
  none: "No guard",
  policy: "Policy engine only",
  full: "Policy engine and muffling",
};

async function loadScorecard() {
  const response = await fetch("/api/scorecard", { headers: headers() });
  if (!response.ok) return;
  const data = await response.json();

  $("score").hidden = false;
  const note = $("score-note");
  note.textContent =
    `${data.runs} runs: ${data.tasks} tasks x (${data.attacks} attacks + one clean control) ` +
    `across three defences. Recorded ${data.generated}. Ranges are 95% Wilson intervals` +
    (data.errored ? `; ${data.errored} run(s) never reached the model and are excluded.` : ".");

  const what = document.createElement("span");
  what.className = "instrument";
  what.textContent = ` Agent: ${data.model}.`;
  note.appendChild(what);

  const body = $("score-table").querySelector("tbody");
  body.textContent = "";
  for (const condition of data.conditions) {
    const tr = document.createElement("tr");
    if (condition.name === "policy") tr.className = "highlight";
    const name = document.createElement("td");
    name.textContent = DEFENCE_NAMES[condition.name] || condition.name;
    if (condition.excluded) {
      const dropped = document.createElement("span");
      dropped.className = "ci";
      dropped.textContent = ` (${condition.excluded} excluded)`;
      name.appendChild(dropped);
    }
    tr.appendChild(name);
    tr.appendChild(rateCell(condition.attack_success, true));
    tr.appendChild(rateCell(condition.attempt_rate, true));
    tr.appendChild(rateCell(condition.stopped_when_attempted, false));
    tr.appendChild(rateCell(condition.task_completion, false));
    body.appendChild(tr);
  }
}

/* ---- wiring ---- */

async function runBoth(event) {
  event.preventDefault();
  const button = $("run");
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.textContent = "Running";
  $("empty").hidden = true;
  $("run-status").classList.remove("is-error");
  $("run-status").textContent = "Starting the unguarded baseline...";

  const request = $("request").value.trim() || config.request;
  const options = {
    request,
    muffle: $("muffle").checked,
    detector: $("detector").checked,
    use_google: $("use-google").checked,
  };

  try {
    await runSides(options);
  } catch {
    $("run-status").classList.add("is-error");
    $("run-status").textContent = "The comparison could not be completed.";
  } finally {
    button.removeAttribute("aria-busy");
    button.disabled = false;
    button.textContent = "Run both";
  }
}

async function runSides(options) {
  let failed = false;
  for (const side of ["unguarded", "guarded"]) {
    const list = $(`trace-${side}`);
    $("run-status").textContent = side === "unguarded"
      ? "Running the unguarded baseline..."
      : "Running the guarded agent...";
    list.textContent = "";
    $(`outcome-${side}`).textContent = "";
    $(`side-${side}`).classList.remove("breached", "held");

    const continued = await stream({ ...options, guarded: side === "guarded" }, (event) => {
      if (event.type === "start") {
        if (event.guarded) lastRunId = event.run_id;
      } else if (event.type === "step") renderStep(list, event);
      else {
        renderOutcome(side, event);
        if (event.error) failed = true;
      }
    });
    if (!continued) break;
  }

  await loadAudit();
  $("run-status").classList.toggle("is-error", failed);
  $("run-status").textContent = failed
    ? "One or more runs failed. Check the messages in each trace."
    : "Both runs finished. Compare the traces and outcomes above.";
}

async function main() {
  let response;
  try {
    let message = "";
    response = await fetch("/api/config", { headers: headers() });
    while (response.status === 401) {
      if (!(await askForPasscode(message))) {
        $("run-mode-label").textContent = "Passcode required";
        $("run-status").textContent = "Unlock the demo before starting a run.";
        return;
      }
      response = await fetch("/api/config", { headers: headers() });
      message = response.status === 401 ? "That passcode was not accepted. Try again." : "";
    }
    if (!response.ok) throw new Error("configuration request failed");
    config = await response.json();
  } catch {
    config = { request: "", model: "unknown", tamper_enabled: false };
    $("run-status").classList.add("is-error");
    $("run-status").textContent = "Could not load the demo configuration.";
  }

  const field = $("request");
  const reset = $("reset-request");
  // loaded with a request it cannot answer, which reads as the app being broken.
  const useDemoRequest = () => {
    field.value = config.request || "";
    reset.hidden = true;
  };
  const mode = $("run-mode");
  const modeLabel = $("run-mode-label");
  mode.classList.toggle("is-replay", Boolean(config.replay_only));
  mode.classList.toggle("is-live", !config.replay_only);
  modeLabel.textContent = config.replay_only ? "Recorded replay" : "Live model available";
  useDemoRequest();
  window.addEventListener("pageshow", useDemoRequest);
  field.addEventListener("input", () => {
    reset.hidden = field.value.trim() === (config.request || "").trim();
  });
  reset.addEventListener("click", useDemoRequest);
  const note = $("request-note");
  note.hidden = false;
  note.textContent = config.replay_only
    ? "Recorded replay: only the bundled request has a fixture. To run custom prompts, configure LLM_API_KEY and an available daily call budget on the server, then redeploy. Never paste a key here."
    : "Custom prompts use the configured live model; the bundled request uses a recorded demo.";
  $("model-note").textContent = `Agent model: ${config.model}`;
  $("tamper").hidden = !config.tamper_enabled;

  const googleStatus = $("google-status");
  const connectGoogle = $("google-connect");
  const disconnectGoogle = $("google-disconnect");
  const useGoogle = $("use-google");
  connectGoogle.hidden = !config.google_configured || config.google_connected;
  disconnectGoogle.hidden = !config.google_connected;
  useGoogle.disabled = !config.google_connected || !config.google_run_available;
  googleStatus.textContent = config.google_connected
    ? !config.google_run_available ? "Google connected; a live model and call budget are required" : "Google account connected"
    : config.google_configured ? "Google account not connected" : "Google OAuth needs server setup";
  const googleResult = new URLSearchParams(location.search).get("google");
  if (googleResult === "connected") googleStatus.textContent = !config.google_run_available
    ? "Google connected; configure a live model and call budget before using data."
    : "Google account connected; choose whether to use its data.";
  if (googleResult === "failed") googleStatus.textContent = "Google sign-in failed. Check the OAuth setup and try again.";
  if (googleResult === "not-configured") googleStatus.textContent = "Google OAuth needs server setup before you can connect.";
  if (googleResult) history.replaceState(null, "", location.pathname);
  disconnectGoogle.addEventListener("click", async () => {
    const response = await fetch("/api/google/disconnect", { method: "POST", headers: headers() });
    if (!response.ok) {
      googleStatus.textContent = "Could not disconnect Google. Reload and try again.";
      return;
    }
    useGoogle.checked = false;
    useGoogle.disabled = true;
    disconnectGoogle.hidden = true;
    connectGoogle.hidden = !config.google_configured;
    googleStatus.textContent = "Google account disconnected";
    config.google_connected = false;
  });

  // Wire the controls first: a scorecard that fails to load must not leave
  // the page without a working Run button.
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

  loadScorecard().catch(() => {});
}

main();
