/* NetLens Command Center — scene controller
 * Keys: 1–6 scene · Enter start/run · Space/→ next step · ← → pick finding (scene 4) · R reset · H hide hints
 * URL:  ?race=live|replay  &lanes=pytorch-cpu,ov-cpu-int8,ov-gpu  &n=152  &narrate=0  &captions=0
 * 旁白模式（預設開）：換場景時自動播放該場景旁白、顯示字幕，並依旁白時間自動起跑／翻卡（data/narration.json）
 *   N 開關旁白模式 · C 開關字幕
 */
const $ = (s, el = document) => el.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const esc = s => s.replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const params = new URLSearchParams(location.search);
const API = "";               // same origin as server.py
const S = { scene: 0, info: null, live: false, tel: [], telNow: { cpu: 0, gpu: 0 },
            narrate: params.get("narrate") !== "0", captions: params.get("captions") !== "0" };
let NARR = null;

/* ───────── stage scaling ───────── */
function fit() {
  const s = Math.min(innerWidth / 1920, innerHeight / 1080);
  $("#stage").style.transform = `scale(${s})`;
}
addEventListener("resize", fit); fit();

/* ───────── boot ───────── */
async function boot() {
  try {
    S.info = await (await fetch(API + "/api/info")).json();
    S.live = true;
    $("#hud-mode").textContent = "●  LIVE";
    $("#hud-mode").className = "pill live";
    const d = S.info.devices;
    $("#hud-hw").textContent = `${d.CPU} · ${d["GPU.0"] || ""} · OpenVINO ${S.info.openvino.split("-")[0]}`;
    if (!params.has("shot")) startTelemetry();   // ?shot=1：無頭截圖用（SSE 不會結束）
    else document.body.classList.add("shot"); 
  } catch {
    $("#hud-mode").textContent = "●  REPLAY";
    $("#hud-mode").className = "pill replay";
    $("#hud-hw").textContent = "server offline — recorded data";
  }
  try { NARR = await getJSON("/data/narration.json"); } catch { NARR = null; }
  $("#stage").classList.toggle("captions-on", S.narrate && S.captions && !!NARR);
  const dots = $("#dots");
  for (let i = 0; i < 6; i++) dots.appendChild(document.createElement("i"));
  go(Number(params.get("scene") || 1));
}

/* ───────── telemetry ───────── */
function startTelemetry() {
  const es = new EventSource(API + "/api/telemetry");
  es.addEventListener("t", e => {
    const v = JSON.parse(e.data);
    S.telNow = v;
    S.tel.push(v); if (S.tel.length > 240) S.tel.shift();
    $("#tl-gpu").textContent = Math.round(v.gpu) + "%";
    $("#tl-cpu").textContent = Math.round(v.cpu) + "%";
    $("#llm-gpu").textContent = Math.round(v.gpu) + "%";
    drawTelemetry();
  });
}
function drawTelemetry() {
  const c = $("#tl-canvas"), g = c.getContext("2d"), W = c.width, H = c.height;
  g.clearRect(0, 0, W, H);
  g.strokeStyle = "rgba(94,200,255,.08)"; g.lineWidth = 1;
  for (const y of [0.25, 0.5, 0.75]) { g.beginPath(); g.moveTo(0, H * y); g.lineTo(W, H * y); g.stroke(); }
  const line = (key, color, glow, fill) => {
    const n = S.tel.length; if (n < 2) return;
    const x = i => W - (n - 1 - i) * (W / 239), y = v => H - 4 - (v / 100) * (H - 8);
    g.beginPath(); S.tel.forEach((p, i) => i ? g.lineTo(x(i), y(p[key])) : g.moveTo(x(i), y(p[key])));
    if (fill) {
      g.save(); g.lineTo(x(n - 1), H); g.lineTo(x(0), H); g.closePath();
      const grd = g.createLinearGradient(0, 0, 0, H); grd.addColorStop(0, fill); grd.addColorStop(1, "transparent");
      g.fillStyle = grd; g.fill(); g.restore();
      g.beginPath(); S.tel.forEach((p, i) => i ? g.lineTo(x(i), y(p[key])) : g.moveTo(x(i), y(p[key])));
    }
    g.strokeStyle = color; g.lineWidth = 2; g.shadowColor = glow; g.shadowBlur = glow ? 12 : 0; g.stroke(); g.shadowBlur = 0;
  };
  line("cpu", "#8b95a7", null, null);
  line("gpu", "#5ec8ff", "#5ec8ff", "rgba(94,200,255,.25)");
}

/* ───────── scene manager ───────── */
let SCENES = {};
let sceneToken = 0;
function go(n) {
  if (!SCENES[n]) return;
  S.scene = n; sceneToken++;
  document.querySelectorAll(".scene").forEach(s => s.classList.toggle("active", s.id === "s" + n));
  document.querySelectorAll("#dots i").forEach((d, i) => d.classList.toggle("on", i === n - 1));
  S.entered = Promise.resolve(SCENES[n].enter?.(sceneToken));
  S.entered.then(() => {
    if (params.has("auto")) setTimeout(() => SCENES[n].start?.(), 300);   // ?auto=1：進場自動開始（截圖/排練用）
  });
  playNarration(n, sceneToken);
}
/* ───────── 旁白 + 字幕 ───────── */
let narrAudio = null;
function stopNarration() {
  if (narrAudio) { narrAudio.pause(); narrAudio = null; }
  $("#caption").classList.remove("on");
}
function playNarration(n, tok) {
  stopNarration();
  const d = NARR?.scenes?.[n];
  if (!S.narrate || !d) return;
  const au = new Audio(d.audio);
  narrAudio = au;
  const fired = new Set(), cap = $("#caption");
  let shown = null;
  au.play().catch(() => {});        // 需使用者按鍵觸發（換場景的按鍵即可）
  const tick = () => {
    if (!alive(tok) || narrAudio !== au) return;
    const t = au.currentTime;
    const c = d.cues.find(q => t >= q.s && t < q.e) || null;
    if (c !== shown) {
      shown = c;
      if (c && S.captions) { cap.textContent = c.text; cap.classList.add("on"); } else cap.classList.remove("on");
    }
    d.actions.forEach((act, i) => {
      if (!fired.has(i) && t >= act.t && !au.paused) {
        fired.add(i);
        S.entered.then(() => alive(tok) && SCENES[n][act.do]?.());
      }
    });
    if (!au.ended) requestAnimationFrame(tick); else cap.classList.remove("on");
  };
  requestAnimationFrame(tick);
}

addEventListener("keydown", e => {
  if (e.key >= "1" && e.key <= "6") return go(Number(e.key));
  if (e.key === "n" || e.key === "N") {
    S.narrate = !S.narrate;
    $("#stage").classList.toggle("captions-on", S.narrate && S.captions && !!NARR);
    return S.narrate ? playNarration(S.scene, sceneToken) : stopNarration();
  }
  if (e.key === "c" || e.key === "C") {
    S.captions = !S.captions;
    $("#stage").classList.toggle("captions-on", S.narrate && S.captions && !!NARR);
    if (!S.captions) $("#caption").classList.remove("on");
    return;
  }
  if (e.key === "h" || e.key === "H") return $("#stage").classList.toggle("hidden-ui");
  if (e.key === "r" || e.key === "R") return go(S.scene);
  const sc = SCENES[S.scene];
  if (e.key === "Enter") sc.start?.();
  else if (e.key === " " || e.key === "ArrowRight") { e.preventDefault(); sc.next?.(); }
  else if (e.key === "ArrowLeft") sc.prev?.();
});
const alive = t => t === sceneToken;

/* shared data */
let FUNNEL = null, RACESET = null, LLMF = null, REPLAY = null;
const getJSON = async p => (await fetch(p)).json();
async function funnelData() { return FUNNEL ??= await getJSON("/data/funnel_healthchecks.json"); }

function countUp(el, to, ms = 1200, dec = 0, from = 0) {
  const t0 = performance.now();
  const tick = now => {
    const k = Math.min(1, (now - t0) / ms), e = 1 - Math.pow(1 - k, 3);
    el.textContent = (from + (to - from) * e).toLocaleString("en-US", { minimumFractionDigits: dec, maximumFractionDigits: dec });
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/* ═════════ 1 · HOOK ═════════ */
// 10 個 OSS 專案（tools/bench_real_projects.py, 2026-09-28）送進模型的 rule 告警總數：217+131+605
const BENCH_ALERTS = 953;
async function hook_enter(tok) {
  const flood = $("#flood"); flood.innerHTML = "";
  ["#hook-1", "#hook-2", "#hook-3"].forEach(s => $(s).classList.remove("show"));
  $("#title-card").classList.remove("show");
  $("#flood-count").textContent = "0";
  let fs = [];
  try { fs = (await funnelData()).findings; } catch {}
  if (!fs.length) fs = [{ file: "app/views.py", line: 42, rule: "sql-injection" }];
  // 時間點對齊旁白（narration_out/cue_sheet.md）：
  //  0–8 s 告警數跳到 953 → 9.3 s "Most are false alarms" → 14.7 s "but for banks…" → 22.6 s "This is NetLens"
  countUp($("#flood-count"), BENCH_ALERTS, 7000);
  const steps = [[2500, () => $("#hook-1").classList.add("show")],
                 [9300, () => $("#hook-2").classList.add("show")],
                 [14700, () => $("#hook-3").classList.add("show")],
                 [22500, () => $("#title-card").classList.add("show")]];
  steps.forEach(([ms, fn]) => setTimeout(() => alive(tok) && fn(), ms));
  hook.skip = () => { steps.forEach(([, fn]) => fn()); };
  let k = 0, spawned = 0;
  while (alive(tok) && spawned < 420) {
    const f = fs[k++ % fs.length];
    const d = document.createElement("div");
    d.className = "alert-card";
    d.style.left = (Math.random() * 1580) + "px";
    d.style.animationDuration = (5 + Math.random() * 4) + "s";
    d.innerHTML = `<b>⚠ ${esc(f.rule)}</b>${esc(f.file)}:${f.line}`;
    flood.appendChild(d);
    setTimeout(() => d.remove(), 9500);
    spawned++;
    await sleep(Math.max(25, 140 - spawned));
  }
}
const hook = { enter: hook_enter, next: () => hook.skip?.(), start: () => hook.skip?.() };

/* ═════════ 2 · FUNNEL ═════════ */
const funnel = {
  async enter(tok) {
    ["confirmed", "disputed", "filtered"].forEach(v => { $("#bin-" + v).innerHTML = ""; $("#c-" + v).textContent = "0"; });
    $("#fn-stream").innerHTML = ""; $("#st-raw").textContent = "0"; $("#st-removed").textContent = "0%"; $("#st-kloc").textContent = "—";
    const d = await funnelData();
    $("#fn-project").textContent = `${d.project} · ${(d.loc / 1000).toFixed(1)}K LOC · ${d.files_scanned} files · ${d.backend.split(" (")[0]}`;
    // 固定順序洗牌（可重現），讓三種判定交錯出現
    let seed = 7; const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
    this.queue = [...d.findings].sort(() => rnd() - .5);
    this.d = d; this.tok = tok; this.running = false;
    this.fill();
    $("#st-raw").textContent = d.findings.length;
  },
  fill() {
    const st = $("#fn-stream");
    for (const f of this.queue.slice(st.children.length, 14)) st.appendChild(this.card(f));
  },
  card(f) {
    const el = document.createElement("div");
    el.className = "f-card";
    const snip = f.hit_code || f.snippet.split("\n").find(l => l.trim()) || "";
    el.innerHTML = `<div class="f-top"><span>${esc(f.rule)}</span><span>${esc(f.file)}:${f.line}</span></div><div class="f-snip">${esc(snip)}</div>`;
    return el;
  },
  async start() {
    if (this.running) return; this.running = true;
    const tok = this.tok, n = { confirmed: 0, disputed: 0, filtered: 0 };
    const kloc = this.d.loc / 1000, total = this.d.findings.length;
    let done = 0;
    while (alive(tok) && this.queue.length) {
      const f = this.queue.shift();
      const el = $("#fn-stream").firstElementChild;
      el.classList.add("scanning");
      $(".fn-chip").classList.remove("pulse-on"); void $(".fn-chip").offsetWidth; $(".fn-chip").classList.add("pulse-on");
      await sleep(260);
      el.classList.add("leave");
      const item = document.createElement("span");
      item.className = "bin-item";
      item.textContent = f.verdict === "filtered" ? `${f.rule}` : `${f.model_name} · ${f.file.split("/").pop()}:${f.line}`;
      const bin = $("#bin-" + f.verdict);
      bin.appendChild(item);
      while (bin.scrollHeight > bin.parentElement.clientHeight - 50 && bin.children.length > 1) bin.firstElementChild.remove();
      n[f.verdict]++; done++;
      $("#c-" + f.verdict).textContent = n[f.verdict];
      $("#st-removed").textContent = Math.round(100 * n.filtered / done) + "%";
      $("#st-kloc").innerHTML = `${(done / kloc).toFixed(2)} → <span class="accent">${((n.confirmed + n.disputed) / kloc).toFixed(2)}</span>`;
      await sleep(260);
      el.remove(); this.fill();
      await sleep(Math.max(60, 380 - done * 6));
    }
  },
};

/* ═════════ 3 · RACE ═════════ */
const race = {
  async enter(tok) {
    this.tok = tok; this.running = false;
    RACESET ??= await getJSON("/data/race_set.json");
    const want = (params.get("lanes") || "").split(",").filter(Boolean);
    this.mode = params.get("race") || (S.live ? "live" : "replay");
    if (this.mode === "replay") {
      try { REPLAY ??= await getJSON("/data/race_replay.json"); } catch { REPLAY = null; }
      this.lanes = Object.keys(REPLAY?.lanes || {}).filter(l => !want.length || want.includes(l));
      $("#race-note").textContent = `each engine measured alone · replayed at recorded timing (${REPLAY?.recorded_at || "—"})`;
      $("#telemetry").style.visibility = "hidden";
    } else {
      this.lanes = Object.keys(S.info.lanes).filter(l => !want.length || want.includes(l));
      $("#race-note").textContent = "live · all engines start at the same time on this laptop";
      $("#telemetry").style.visibility = "visible";
    }
    this.n = Math.min(Number(params.get("n") || 152), RACESET.items.length);
    const box = $("#race"); box.innerHTML = "";
    box.style.gridTemplateColumns = `repeat(${this.lanes.length}, 1fr)`;
    // 依賽道數決定欄數，讓方塊盡量填滿面板高度
    const cols = this.lanes.length >= 3 ? 14 : this.lanes.length === 2 ? 17 : 26;
    for (const l of this.lanes) {
      const name = (S.info?.lanes?.[l]) || REPLAY?.lanes?.[l]?.name || l;
      const [eng, dev] = name.split(" · ");
      const intel = l.startsWith("ov");
      const devName = l.endsWith("cpu") || l === "ov-cpu-int8" ? (S.info?.devices?.CPU || REPLAY?.info?.devices?.CPU || "CPU")
                                      : (S.info?.devices?.["GPU.0"] || REPLAY?.info?.devices?.["GPU.0"] || "Intel GPU");
      const el = document.createElement("div");
      el.className = "lane" + (intel ? " intel" : ""); el.id = "lane-" + l;
      el.innerHTML = `
        <div class="lane-head"><div><div class="lane-name">${esc(eng)}</div><div class="lane-dev">${esc(dev)} · ${esc(devName)}</div></div>
          <div class="lane-fps"><div class="n">0.0</div><div class="u">functions / s</div></div></div>
        <div class="tiles" style="grid-template-columns:repeat(${cols},1fr)">${'<i class="tile"></i>'.repeat(this.n)}</div>
        <div class="lane-ticker">waiting…</div>
        <div class="lane-bottom"><span class="cnt">0 / ${this.n}</span><div class="prog"><i></i></div><span class="clock">0.0 s</span></div>
        <div class="finish"></div>`;
      box.appendChild(el);
    }
    $("#race-hint").innerHTML = "press <kbd>Enter</kbd> to start";
  },
  start() {
    if (this.running) return; this.running = true; this.finished = 0;
    $("#race-hint").textContent = "";
    const t0 = performance.now();
    for (const l of this.lanes) {
      const st = { k: 0, t0, done: false };
      const el = $("#lane-" + l);
      const clock = setInterval(() => {
        if (!alive(this.tok)) return clearInterval(clock);
        const s = (performance.now() - t0) / 1000;
        $(".clock", el).textContent = s.toFixed(1) + " s";
        if (st.k) $(".lane-fps .n", el).textContent = (st.k / s).toFixed(1);
      }, 100);
      const onItem = it => this.item(el, st, it);
      const onDone = d => { clearInterval(clock); this.finish(el, st, d); };
      if (this.mode === "live") {
        const es = new EventSource(`${API}/api/race?lane=${l}&n=${this.n}`);
        es.addEventListener("item", e => alive(this.tok) && onItem(JSON.parse(e.data)));
        es.addEventListener("done", e => { es.close(); alive(this.tok) && onDone(JSON.parse(e.data)); });
        es.onerror = () => es.close();
      } else {
        const lane = REPLAY.lanes[l];
        const evs = lane.events.filter(e => e.i < this.n);
        evs.forEach(e => setTimeout(() => alive(this.tok) && onItem(e), e.t));
        const last = evs.at(-1).t;
        setTimeout(() => alive(this.tok) && onDone({ elapsed_s: last / 1000, fps: evs.length / (last / 1000), n: evs.length }), last + 30);
      }
    }
  },
  item(el, st, it) {
    st.k++;
    const tile = el.querySelectorAll(".tile")[it.i];
    tile.classList.add(it.pred === 0 ? "benign" : "vuln", "flash");
    setTimeout(() => tile.classList.remove("flash"), 180);
    const src = RACESET.items[it.i];
    $(".lane-ticker", el).textContent = `${it.pred === 0 ? "✓ benign" : "⚠ " + LABELS[it.pred]} · ${src.lang} · ${src.preview}`;
    $(".cnt", el).textContent = `${st.k} / ${this.n}`;
    $(".prog i", el).style.width = (100 * st.k / this.n) + "%";
  },
  finish(el, st, d) {
    this.finished++;
    const s = Number(d.elapsed_s);
    $(".clock", el).textContent = s.toFixed(1) + " s";
    $(".lane-fps .n", el).textContent = (st.k / s).toFixed(1);
    const place = ["1st", "2nd", "3rd", "4th"][this.finished - 1];
    $(".finish", el).innerHTML = `${place} · ${s.toFixed(1)} s<small>${st.k} functions · ${(st.k / s).toFixed(1)} / s</small>`;
    el.classList.add("done");
    if (this.finished === this.lanes.length) $("#race-hint").innerHTML = "<kbd>R</kbd> reset";
  },
};
const LABELS = ["Benign", "Command Injection", "SQL Injection", "Code Execution", "Data Exposure", "Backdoor",
  "Weak Crypto", "Hardcoded Secret", "Path Traversal", "Insecure Deserialization", "XSS", "Prototype Pollution",
  "Malicious Package", "CSRF", "SSRF", "Unrestricted Upload", "Broken Access Control"];

/* ═════════ 4 · LLM ═════════ */
const llm = {
  idx: 0,
  async enter(tok) {
    this.tok = tok; this.running = false;
    LLMF ??= await getJSON("/data/llm_findings.json");
    const want = params.get("finding");
    if (want) this.idx = Math.max(0, LLMF.findIndex(f => f.id === want));
    if (S.narrate && NARR) this.idx = 0;
    this.show();
  },
  show() {
    const f = LLMF[this.idx];
    const hit = this.hitLines(f);
    $("#llm-file").textContent = `${f.file} · line ${[...hit][0] || f.line}`;
    $("#llm-chips").innerHTML = `<span class="chip">Semgrep · ${esc(f.semgrep_rule.split(".").pop())}</span><span class="chip chip-crit">CodeBERT · ${esc(f.category)}</span>`;
    $("#llm-code").innerHTML = f.code.replace(/\n$/, "").split("\n")
      .map((l, i) => `<span class="ln${hit.has(i + 1) ? " hit" : ""}" data-n="${i + 1}">${esc(l) || " "}</span>`).join("");
    $("#llm-out").innerHTML = '<span class="h">Waiting for finding…</span>';
    $("#llm-diff-wrap").classList.remove("show"); $("#llm-diff").innerHTML = "";
    ["#llm-ttft", "#llm-tps", "#llm-tok"].forEach(s => $(s).textContent = "—");
    $(".pulse").classList.remove("on");
    $("#llm-hint").innerHTML = `${f.id} of ${LLMF.length} · ← → choose finding · <kbd>Enter</kbd> run`;
  },
  hitLines(f) {
    // 高亮 sink 所在行：依類別找關鍵 API
    const pat = { "CWE-89": /execute\(|query =/, "CWE-78": /exec\(|command =/, "CWE-502": /readObject|ObjectInputStream\(/,
                  "CWE-79": /html =|<h1>/, "CWE-22": /path\.join|readFile/ }[(f.category.match(/CWE-\d+/) || [""])[0]];
    const s = new Set();
    f.code.split("\n").forEach((l, i) => pat && pat.test(l) && s.add(i + 1));
    return s;
  },
  next() { if (!this.running) { this.idx = (this.idx + 1) % LLMF.length; this.show(); } },
  prev() { if (!this.running) { this.idx = (this.idx - 1 + LLMF.length) % LLMF.length; this.show(); } },
  start() {
    if (this.running || !S.live) return; this.running = true;
    const f = LLMF[this.idx], tok = this.tok, out = $("#llm-out");
    let text = "", n = 0, t0 = performance.now(), tFirst = 0;
    $(".pulse").classList.add("on"); $("#llm-hint").textContent = "";
    out.innerHTML = '<span class="caret"></span>';
    const es = new EventSource(`${API}/api/llm?id=${f.id}`);
    es.addEventListener("token", e => {
      if (!alive(tok)) return es.close();
      if (!n) { tFirst = performance.now(); $("#llm-ttft").textContent = Math.round(tFirst - t0) + " ms"; }
      n++; text += JSON.parse(e.data).t;
      out.innerHTML = this.render(text) + '<span class="caret"></span>';
      out.scrollTop = out.scrollHeight;
      $("#llm-tok").textContent = n;
      if (n > 3) $("#llm-tps").textContent = ((n - 1) / ((performance.now() - tFirst) / 1000)).toFixed(1) + " tok/s";
    });
    es.addEventListener("done", e => {
      es.close(); if (!alive(tok)) return;
      const d = JSON.parse(e.data);
      out.innerHTML = this.render(text);
      $("#llm-ttft").textContent = Math.round(d.ttft_ms) + " ms";
      $("#llm-tps").textContent = d.tokens_per_s + " tok/s";
      $("#llm-tok").textContent = d.output_tokens;
      $(".pulse").classList.remove("on");
      if (d.diff) {
        // 解釋留在上方，程式碼區塊收起，讓位給 diff
        out.innerHTML = this.render(text.split(/### Fixed code/)[0]);
        const lines = d.diff.replace(/\n$/, "").split("\n");
        $("#llm-diff").innerHTML = lines.map((l, i) => {
          const c = l.startsWith("+++") || l.startsWith("---") || l.startsWith("@@") ? "meta" : l[0] === "+" ? "add" : l[0] === "-" ? "del" : "";
          return `<span class="${c}" style="animation-delay:${i * 70}ms">${esc(l) || " "}</span>`;
        }).join("");
        $("#llm-diff-wrap").classList.add("show");
      }
      this.running = false;
      $("#llm-hint").innerHTML = "← → choose finding · <kbd>Enter</kbd> run";

    });
    es.onerror = () => { es.close(); this.running = false; };
  },
  render(t) {
    let inCode = false;
    return t.split("\n").map(l => {
      if (l.startsWith("```")) { inCode = !inCode; return ""; }
      if (inCode) return `<span class="cb">${esc(l)}</span>`;
      if (l.startsWith("###")) return `<span class="h">${esc(l.replace(/^#+\s*/, ""))}</span>`;
      return esc(l);
    }).filter((l, i, a) => l !== "" || (i && a[i - 1] !== "")).join("\n");
  },
};

/* ═════════ 5 · CARDS ═════════ */
const LATENCY = [
  { lbl: "PyTorch FP32", sub: "Intel CPU · baseline", ms: 336, cls: "base", val: "336 ms" },
  { lbl: "OpenVINO INT8", sub: "Intel CPU", ms: 141, cls: "ov", val: "141 ms" },
  { lbl: "OpenVINO", sub: "Intel integrated GPU", ms: 93, cls: "ov", val: "93 ms" },
  { lbl: "Arc Pro B70 · INT8", sub: "projected from 367 TOPS", ms: 5, cls: "proj", val: "~3–5 ms", proj: true },
];
const cards = {
  enter() {
    $("#lat-bars").innerHTML = LATENCY.map(r => `
      <div class="bar-row"><div class="lbl">${r.lbl}${r.proj ? '<span class="proj-tag">PROJECTED</span>' : ""}<small>${r.sub}</small></div>
      <div><div class="bar ${r.cls}" style="--w:${Math.max(1.2, 100 * r.ms / 336)}%"></div></div>
      <div class="val ${r.proj ? "violet" : r.cls === "ov" ? "accent" : ""}">${r.val}</div></div>`).join("");
    this.i = Number(params.get("card") || 0) - 1; this.next();
  },
  next() {
    const all = document.querySelectorAll(".card");
    this.i = Math.min(this.i + 1, all.length - 1);
    all.forEach((c, k) => c.classList.toggle("show", k === this.i));
    all[this.i].querySelectorAll(".count").forEach(el =>
      countUp(el, Number(el.dataset.to), 1600, Number(el.dataset.dec || 0), Number(el.dataset.from || 0)));
  },
  prev() { this.i = Math.max(-1, this.i - 2); this.next(); },
};

/* ═════════ 6 · ARCH ═════════ */
const arch = {};

SCENES = { 1: hook, 2: funnel, 3: race, 4: llm, 5: cards, 6: arch };
boot();
