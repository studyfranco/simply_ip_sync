"use strict";

/* ---------------------------------------------------------------------- *
 * Pure-JS SHA-256 / HMAC-SHA256 fallback.
 *
 * crypto.subtle is only available in a secure context (HTTPS or localhost),
 * and this dashboard is routinely used over plain HTTP on a LAN. The
 * fallback below is not constant-time, but on plain HTTP the request and
 * its headers are already fully visible on the wire, so a JS timing
 * side-channel adds no new exposure beyond what the transport already
 * concedes.
 * ---------------------------------------------------------------------- */

function sha256Bytes(bytes) {
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const bitLen = bytes.length * 8;
  const withOne = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  withOne.set(bytes);
  withOne[bytes.length] = 0x80;
  const dv = new DataView(withOne.buffer);
  dv.setUint32(withOne.length - 4, bitLen >>> 0, false);
  dv.setUint32(withOne.length - 8, Math.floor(bitLen / 0x100000000), false);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < withOne.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + K[i] + w[i]) | 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) | 0;
      h = g; g = f; f = e; e = (d + temp1) | 0;
      d = c; c = b; b = a; a = (temp1 + temp2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => odv.setUint32(i * 4, v >>> 0, false));
  return out;
}

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function hmacSha256Fallback(keyBytes, msgBytes) {
  const blockSize = 64;
  let key = keyBytes;
  if (key.length > blockSize) key = sha256Bytes(key);
  if (key.length < blockSize) {
    const padded = new Uint8Array(blockSize);
    padded.set(key);
    key = padded;
  }
  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    oKeyPad[i] = key[i] ^ 0x5c;
    iKeyPad[i] = key[i] ^ 0x36;
  }
  const inner = sha256Bytes(concatBytes(iKeyPad, msgBytes));
  return sha256Bytes(concatBytes(oKeyPad, inner));
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const keyBytes = enc.encode(secret);
  const msgBytes = message instanceof Uint8Array ? message : enc.encode(message);
  const hasSubtle = typeof crypto !== "undefined" && crypto.subtle && typeof crypto.subtle.importKey === "function";
  if (hasSubtle) {
    try {
      const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
      return bytesToHex(new Uint8Array(sig));
    } catch (e) {
      // fall through to the pure-JS implementation
    }
  }
  return bytesToHex(hmacSha256Fallback(keyBytes, msgBytes));
}

/* ---------------------------------------------------------------------- *
 * Signed API client.
 * ---------------------------------------------------------------------- */

class SyncClient {
  constructor(apiKey, signingSecret) {
    this.apiKey = apiKey;
    this.signingSecret = signingSecret;
  }

  async request(method, path, body) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const bodyBytes = body !== undefined ? new TextEncoder().encode(JSON.stringify(body)) : new Uint8Array(0);
    const message = new TextEncoder().encode(`${method}\n${path}\n${timestamp}\n`);
    const full = concatBytes(message, bodyBytes);
    const signature = "sha256=" + (await hmacSha256Hex(this.signingSecret, full));

    const headers = {
      "X-API-Key": this.apiKey,
      "X-Timestamp": timestamp,
      "X-Signature-256": signature,
    };
    if (body !== undefined) headers["Content-Type"] = "application/json";

    const resp = await fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await resp.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (e) {
      data = text;
    }
    if (!resp.ok) {
      const message = (data && data.error) || `HTTP ${resp.status}`;
      const err = new Error(message);
      err.status = resp.status;
      err.body = data;
      throw err;
    }
    return data;
  }

  get(path) { return this.request("GET", path); }
  post(path, body) { return this.request("POST", path, body ?? {}); }
  patch(path, body) { return this.request("PATCH", path, body ?? {}); }
  put(path, body) { return this.request("PUT", path, body ?? {}); }
  del(path) { return this.request("DELETE", path); }
}

/* ---------------------------------------------------------------------- *
 * App state & bootstrap.
 * ---------------------------------------------------------------------- */

let client = null;
let me = null;

function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const apiKey = document.getElementById("login-api-key").value.trim();
  const signingSecret = document.getElementById("login-signing-secret").value.trim();
  const candidate = new SyncClient(apiKey, signingSecret);
  try {
    me = await candidate.get("/api/auth/me");
    client = candidate;
    document.getElementById("login-screen").classList.add("hidden");
    document.getElementById("app").classList.remove("hidden");
    renderIdentity();
    setupTabs();
    await loadTab("sources");
  } catch (err) {
    toast("Sign-in failed: " + err.message, "err");
  }
});

function renderIdentity() {
  const rights = [];
  if (me.is_master) rights.push("MASTER");
  if (me.can_manage_keys) rights.push("can_manage_keys");
  if (me.can_manage_sources) rights.push("can_manage_sources");
  if (me.can_manage_vaults) rights.push("can_manage_vaults");
  document.getElementById("identity").innerHTML =
    `<span>${escapeHtml(me.name)}</span>` + rights.map((r) => `<span class="badge">${escapeHtml(r)}</span>`).join("");
  if (!me.is_master) {
    document.querySelector('nav button[data-tab="audit-logs"]').classList.add("hidden");
  }
}

function setupTabs() {
  document.querySelectorAll("nav button[data-tab]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      document.querySelectorAll("nav button[data-tab]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.add("hidden"));
      const panel = document.getElementById("tab-" + btn.dataset.tab);
      panel.classList.remove("hidden");
      await loadTab(btn.dataset.tab);
    });
  });
}

async function loadTab(tab) {
  try {
    if (tab === "sources") await renderSources();
    else if (tab === "sync-tasks") await renderSyncTasks();
    else if (tab === "vaults") await renderVaults();
    else if (tab === "keys") await renderKeys();
    else if (tab === "sync-logs") await renderSyncLogs();
    else if (tab === "audit-logs") await renderAuditLogs();
  } catch (err) {
    toast("Failed to load: " + err.message, "err");
  }
}

/* ---------------------------------------------------------------------- *
 * Sources
 * ---------------------------------------------------------------------- */

async function renderSources() {
  const panel = document.getElementById("tab-sources");
  const sources = await client.get("/api/sources");
  const vaults = await client.get("/api/vaults").catch(() => []);
  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h2>External Sources</h2>
        ${me.is_master || me.can_manage_sources ? '<button class="btn btn-primary" id="new-source-btn">+ New Source</button>' : ""}
      </div>
      <div id="source-form-slot"></div>
      <table>
        <thead><tr><th>Name</th><th>URL</th><th>Parser</th><th>Schedule</th><th>Group</th><th>Active</th><th>Last Run</th><th></th></tr></thead>
        <tbody>
          ${sources.length ? sources.map(sourceRow).join("") : '<tr><td colspan="8" class="empty">No sources yet.</td></tr>'}
        </tbody>
      </table>
    </div>`;

  if (document.getElementById("new-source-btn")) {
    document.getElementById("new-source-btn").addEventListener("click", () => showSourceForm(null, vaults));
  }
  panel.querySelectorAll("[data-edit-source]").forEach((btn) =>
    btn.addEventListener("click", () => showSourceForm(sources.find((s) => s.id === btn.dataset.editSource), vaults))
  );
  panel.querySelectorAll("[data-delete-source]").forEach((btn) =>
    btn.addEventListener("click", () => deleteResource("/api/sources/" + btn.dataset.deleteSource, "sources"))
  );
  panel.querySelectorAll("[data-trigger-source]").forEach((btn) =>
    btn.addEventListener("click", () => triggerResource("/api/sources/" + btn.dataset.triggerSource + "/trigger"))
  );
}

function sourceRow(s) {
  return `<tr>
    <td>${escapeHtml(s.name)}</td>
    <td class="mono">${escapeHtml(s.source_url)}</td>
    <td>${escapeHtml(s.parser_type)}</td>
    <td class="mono">${escapeHtml(s.cron_schedule)}</td>
    <td>${escapeHtml(s.target_group_name)}</td>
    <td>${s.is_active ? "yes" : "no"}</td>
    <td>${escapeHtml(s.last_run_at || "never")}</td>
    <td class="row-actions">
      <button class="btn btn-sm" data-trigger-source="${s.id}">Trigger</button>
      <button class="btn btn-sm" data-edit-source="${s.id}">Edit</button>
      <button class="btn btn-sm btn-danger" data-delete-source="${s.id}">Delete</button>
    </td>
  </tr>`;
}

function showSourceForm(existing, vaults) {
  const slot = document.getElementById("source-form-slot");
  const vaultOptions = vaults.map((v) => `<option value="${v.id}">${escapeHtml(v.name)}</option>`).join("");
  slot.innerHTML = `
    <form class="inline-form" id="source-form">
      <label>Name<input name="name" required value="${escapeHtml(existing?.name || "")}"></label>
      <label>Source URL<input name="source_url" required value="${escapeHtml(existing?.source_url || "")}"></label>
      <label>Parser Type
        <select name="parser_type">
          <option value="REGEX_LINE" ${existing?.parser_type === "REGEX_LINE" ? "selected" : ""}>REGEX_LINE</option>
          <option value="JSON_PATH" ${existing?.parser_type === "JSON_PATH" ? "selected" : ""}>JSON_PATH</option>
        </select>
      </label>
      <label>Cron Schedule<input name="cron_schedule" required placeholder="0 0 * * *" value="${escapeHtml(existing?.cron_schedule || "")}"></label>
      <label>Target Group Name<input name="target_group_name" required value="${escapeHtml(existing?.target_group_name || "")}"></label>
      <label>Active
        <select name="is_active">
          <option value="true" ${existing?.is_active !== false ? "selected" : ""}>true</option>
          <option value="false" ${existing?.is_active === false ? "selected" : ""}>false</option>
        </select>
      </label>
      <label class="span-2">Parser Config JSON<textarea name="parser_config_json">${escapeHtml(existing?.parser_config_json || "")}</textarea></label>
      <label class="span-2">Target Vaults (select one or more)
        <select name="targets" multiple size="4">${vaultOptions}</select>
      </label>
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">${existing ? "Save" : "Create"}</button>
        <button type="button" class="btn" id="source-form-cancel">Cancel</button>
      </div>
    </form>`;

  if (existing) {
    const selected = new Set((existing.targets || []).map((t) => t.vault_endpoint_id));
    slot.querySelectorAll('select[name="targets"] option').forEach((opt) => {
      if (selected.has(opt.value)) opt.selected = true;
    });
  }

  document.getElementById("source-form-cancel").addEventListener("click", () => (slot.innerHTML = ""));
  document.getElementById("source-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const targets = Array.from(e.target.querySelector('select[name="targets"]').selectedOptions).map((o) => ({
      vault_endpoint_id: o.value,
    }));
    const payload = {
      name: fd.get("name"),
      source_url: fd.get("source_url"),
      parser_type: fd.get("parser_type"),
      cron_schedule: fd.get("cron_schedule"),
      target_group_name: fd.get("target_group_name"),
      is_active: fd.get("is_active") === "true",
      parser_config_json: fd.get("parser_config_json") || null,
      targets,
    };
    try {
      if (existing) await client.patch("/api/sources/" + existing.id, payload);
      else await client.post("/api/sources", payload);
      toast("Source saved", "ok");
      slot.innerHTML = "";
      await renderSources();
    } catch (err) {
      toast("Save failed: " + err.message, "err");
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Sync tasks
 * ---------------------------------------------------------------------- */

async function renderSyncTasks() {
  const panel = document.getElementById("tab-sync-tasks");
  const tasks = await client.get("/api/sync-tasks");
  const vaults = await client.get("/api/vaults").catch(() => []);
  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h2>Inter-Vault Sync Tasks</h2>
        ${me.is_master || me.can_manage_vaults ? '<button class="btn btn-primary" id="new-task-btn">+ New Task</button>' : ""}
      </div>
      <div id="task-form-slot"></div>
      <table>
        <thead><tr><th>Name</th><th>Source Vault</th><th>Source Group</th><th>Target Group</th><th>Schedule</th><th>Active</th><th>Last Sync</th><th></th></tr></thead>
        <tbody>
          ${tasks.length ? tasks.map((t) => taskRow(t, vaults)).join("") : '<tr><td colspan="8" class="empty">No sync tasks yet.</td></tr>'}
        </tbody>
      </table>
    </div>`;

  if (document.getElementById("new-task-btn")) {
    document.getElementById("new-task-btn").addEventListener("click", () => showTaskForm(null, vaults));
  }
  panel.querySelectorAll("[data-edit-task]").forEach((btn) =>
    btn.addEventListener("click", () => showTaskForm(tasks.find((t) => t.id === btn.dataset.editTask), vaults))
  );
  panel.querySelectorAll("[data-delete-task]").forEach((btn) =>
    btn.addEventListener("click", () => deleteResource("/api/sync-tasks/" + btn.dataset.deleteTask, "sync-tasks"))
  );
  panel.querySelectorAll("[data-trigger-task]").forEach((btn) =>
    btn.addEventListener("click", () => triggerResource("/api/sync-tasks/" + btn.dataset.triggerTask + "/trigger"))
  );
}

function taskRow(t, vaults) {
  const sourceVault = vaults.find((v) => v.id === t.source_vault_id);
  return `<tr>
    <td>${escapeHtml(t.name)}</td>
    <td>${escapeHtml(sourceVault?.name || t.source_vault_id)}</td>
    <td>${escapeHtml(t.source_group_name)}</td>
    <td>${escapeHtml(t.target_group_name)}</td>
    <td class="mono">${escapeHtml(t.cron_schedule)}</td>
    <td>${t.is_active ? "yes" : "no"}</td>
    <td>${escapeHtml(t.last_sync_at || "never")}</td>
    <td class="row-actions">
      <button class="btn btn-sm" data-trigger-task="${t.id}">Trigger</button>
      <button class="btn btn-sm" data-edit-task="${t.id}">Edit</button>
      <button class="btn btn-sm btn-danger" data-delete-task="${t.id}">Delete</button>
    </td>
  </tr>`;
}

function showTaskForm(existing, vaults) {
  const slot = document.getElementById("task-form-slot");
  const vaultOptions = vaults.map((v) => `<option value="${v.id}">${escapeHtml(v.name)}</option>`).join("");
  slot.innerHTML = `
    <form class="inline-form" id="task-form">
      <label>Name<input name="name" required value="${escapeHtml(existing?.name || "")}"></label>
      <label>Source Vault
        <select name="source_vault_id" required>${vaultOptions}</select>
      </label>
      <label>Source Group Name<input name="source_group_name" required value="${escapeHtml(existing?.source_group_name || "")}"></label>
      <label>Target Group Name<input name="target_group_name" required value="${escapeHtml(existing?.target_group_name || "")}"></label>
      <label>Cron Schedule<input name="cron_schedule" required placeholder="0 * * * *" value="${escapeHtml(existing?.cron_schedule || "")}"></label>
      <label>Active
        <select name="is_active">
          <option value="true" ${existing?.is_active !== false ? "selected" : ""}>true</option>
          <option value="false" ${existing?.is_active === false ? "selected" : ""}>false</option>
        </select>
      </label>
      <label class="span-2">Target Vaults (select one or more)
        <select name="targets" multiple size="4">${vaultOptions}</select>
      </label>
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">${existing ? "Save" : "Create"}</button>
        <button type="button" class="btn" id="task-form-cancel">Cancel</button>
      </div>
    </form>`;

  if (existing) {
    slot.querySelector('select[name="source_vault_id"]').value = existing.source_vault_id;
    const selected = new Set((existing.targets || []).map((t) => t.vault_endpoint_id));
    slot.querySelectorAll('select[name="targets"] option').forEach((opt) => {
      if (selected.has(opt.value)) opt.selected = true;
    });
  }

  document.getElementById("task-form-cancel").addEventListener("click", () => (slot.innerHTML = ""));
  document.getElementById("task-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const targets = Array.from(e.target.querySelector('select[name="targets"]').selectedOptions).map((o) => ({
      vault_endpoint_id: o.value,
    }));
    const payload = {
      name: fd.get("name"),
      source_vault_id: fd.get("source_vault_id"),
      source_group_name: fd.get("source_group_name"),
      target_group_name: fd.get("target_group_name"),
      cron_schedule: fd.get("cron_schedule"),
      is_active: fd.get("is_active") === "true",
      targets,
    };
    try {
      if (existing) await client.patch("/api/sync-tasks/" + existing.id, payload);
      else await client.post("/api/sync-tasks", payload);
      toast("Sync task saved", "ok");
      slot.innerHTML = "";
      await renderSyncTasks();
    } catch (err) {
      toast("Save failed: " + err.message, "err");
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Vaults
 * ---------------------------------------------------------------------- */

async function renderVaults() {
  const panel = document.getElementById("tab-vaults");
  const vaults = await client.get("/api/vaults");
  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h2>Vault Endpoints</h2>
        ${me.is_master || me.can_manage_vaults ? '<button class="btn btn-primary" id="new-vault-btn">+ New Vault</button>' : ""}
      </div>
      <div id="vault-form-slot"></div>
      <table>
        <thead><tr><th>Name</th><th>Target URL</th><th>Description</th><th></th></tr></thead>
        <tbody>
          ${vaults.length ? vaults.map(vaultRow).join("") : '<tr><td colspan="4" class="empty">No vault endpoints yet.</td></tr>'}
        </tbody>
      </table>
    </div>`;

  if (document.getElementById("new-vault-btn")) {
    document.getElementById("new-vault-btn").addEventListener("click", () => showVaultForm(null));
  }
  panel.querySelectorAll("[data-edit-vault]").forEach((btn) =>
    btn.addEventListener("click", () => showVaultForm(vaults.find((v) => v.id === btn.dataset.editVault)))
  );
  panel.querySelectorAll("[data-delete-vault]").forEach((btn) =>
    btn.addEventListener("click", () => deleteResource("/api/vaults/" + btn.dataset.deleteVault, "vaults"))
  );
}

function vaultRow(v) {
  return `<tr>
    <td>${escapeHtml(v.name)}</td>
    <td class="mono">${escapeHtml(v.target_url)}</td>
    <td>${escapeHtml(v.description || "")}</td>
    <td class="row-actions">
      <button class="btn btn-sm" data-edit-vault="${v.id}">Edit</button>
      <button class="btn btn-sm btn-danger" data-delete-vault="${v.id}">Delete</button>
    </td>
  </tr>`;
}

function showVaultForm(existing) {
  const slot = document.getElementById("vault-form-slot");
  slot.innerHTML = `
    <form class="inline-form" id="vault-form">
      <label>Name<input name="name" required value="${escapeHtml(existing?.name || "")}"></label>
      <label>Target URL<input name="target_url" required value="${escapeHtml(existing?.target_url || "")}"></label>
      <label>Remote X-API-Key${existing ? " (leave blank to keep)" : ""}<input name="api_key" ${existing ? "" : "required"}></label>
      <label>Remote Signing Secret${existing ? " (leave blank to keep)" : ""}<input name="signing_secret" ${existing ? "" : "required"}></label>
      <label class="span-2">Description<input name="description" value="${escapeHtml(existing?.description || "")}"></label>
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">${existing ? "Save" : "Create"}</button>
        <button type="button" class="btn" id="vault-form-cancel">Cancel</button>
      </div>
    </form>`;

  document.getElementById("vault-form-cancel").addEventListener("click", () => (slot.innerHTML = ""));
  document.getElementById("vault-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const payload = {
      name: fd.get("name"),
      target_url: fd.get("target_url"),
      description: fd.get("description") || null,
    };
    if (fd.get("api_key")) payload.api_key = fd.get("api_key");
    if (fd.get("signing_secret")) payload.signing_secret = fd.get("signing_secret");
    try {
      if (existing) await client.patch("/api/vaults/" + existing.id, payload);
      else await client.post("/api/vaults", payload);
      toast("Vault endpoint saved", "ok");
      slot.innerHTML = "";
      await renderVaults();
    } catch (err) {
      toast("Save failed: " + err.message, "err");
    }
  });
}

/* ---------------------------------------------------------------------- *
 * Keys
 * ---------------------------------------------------------------------- */

async function renderKeys() {
  const panel = document.getElementById("tab-keys");
  const keys = await client.get("/api/keys");
  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h2>API Keys</h2>
        ${me.is_master || me.can_manage_keys ? '<button class="btn btn-primary" id="new-key-btn">+ New Key</button>' : ""}
      </div>
      <div id="key-form-slot"></div>
      <table>
        <thead><tr><th>Name</th><th>Prefix</th><th>Rights</th><th>Parent</th><th></th></tr></thead>
        <tbody>
          ${keys.length ? keys.map(keyRow).join("") : '<tr><td colspan="5" class="empty">No keys visible.</td></tr>'}
        </tbody>
      </table>
    </div>`;

  if (document.getElementById("new-key-btn")) {
    document.getElementById("new-key-btn").addEventListener("click", () => showKeyForm());
  }
  panel.querySelectorAll("[data-rotate-key]").forEach((btn) =>
    btn.addEventListener("click", () => rotateKey(btn.dataset.rotateKey))
  );
  panel.querySelectorAll("[data-rotate-secret]").forEach((btn) =>
    btn.addEventListener("click", () => rotateSecret(btn.dataset.rotateSecret))
  );
  panel.querySelectorAll("[data-delete-key]").forEach((btn) =>
    btn.addEventListener("click", () => deleteResource("/api/keys/" + btn.dataset.deleteKey, "keys"))
  );
}

function keyRow(k) {
  const rights = [k.is_master && "MASTER", k.can_manage_keys && "keys", k.can_manage_sources && "sources", k.can_manage_vaults && "vaults"]
    .filter(Boolean)
    .join(", ");
  const actions = k.is_master
    ? ""
    : `<button class="btn btn-sm" data-rotate-key="${k.id}">Rotate Key</button>
       <button class="btn btn-sm" data-rotate-secret="${k.id}">Rotate Secret</button>
       <button class="btn btn-sm btn-danger" data-delete-key="${k.id}">Delete</button>`;
  return `<tr>
    <td>${escapeHtml(k.name)}</td>
    <td class="mono">${escapeHtml(k.prefix)}</td>
    <td>${escapeHtml(rights)}</td>
    <td class="mono">${escapeHtml(k.parent_key_id || "")}</td>
    <td class="row-actions">${actions}</td>
  </tr>`;
}

function showKeyForm() {
  const slot = document.getElementById("key-form-slot");
  slot.innerHTML = `
    <form class="inline-form" id="key-form">
      <label>Name<input name="name" required></label>
      <label>Bound IPs (CIDR, comma-separated)<input name="bound_ips" placeholder="0.0.0.0/0,::/0"></label>
      ${me.is_master ? `
      <label>can_manage_keys <input type="checkbox" name="can_manage_keys"></label>
      <label>can_manage_sources <input type="checkbox" name="can_manage_sources"></label>
      <label>can_manage_vaults <input type="checkbox" name="can_manage_vaults"></label>
      ` : ""}
      <div class="form-actions">
        <button type="submit" class="btn btn-primary">Create</button>
        <button type="button" class="btn" id="key-form-cancel">Cancel</button>
      </div>
    </form>`;

  document.getElementById("key-form-cancel").addEventListener("click", () => (slot.innerHTML = ""));
  document.getElementById("key-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const payload = {
      name: fd.get("name"),
      bound_ips: fd.get("bound_ips") || null,
      can_manage_keys: fd.get("can_manage_keys") === "on",
      can_manage_sources: fd.get("can_manage_sources") === "on",
      can_manage_vaults: fd.get("can_manage_vaults") === "on",
    };
    try {
      const result = await client.post("/api/keys", payload);
      slot.innerHTML = "";
      await renderKeys();
      alert(
        "Save these now — they will not be shown again:\n\n" +
          "API Key: " + result.plaintext_key + "\n" +
          "Signing Secret: " + result.plaintext_signing_secret
      );
    } catch (err) {
      toast("Create failed: " + err.message, "err");
    }
  });
}

async function rotateKey(id) {
  if (!confirm("Rotate this key's plaintext credential? The old one stops working immediately.")) return;
  try {
    const result = await client.post("/api/keys/" + id + "/rotate");
    alert("New API key (save this now):\n\n" + result.plaintext_key);
  } catch (err) {
    toast("Rotation failed: " + err.message, "err");
  }
}

async function rotateSecret(id) {
  if (!confirm("Rotate this key's signing secret? The old one stops working immediately.")) return;
  try {
    const result = await client.post("/api/keys/" + id + "/rotate-secret");
    alert("New signing secret (save this now):\n\n" + result.plaintext_signing_secret);
  } catch (err) {
    toast("Rotation failed: " + err.message, "err");
  }
}

/* ---------------------------------------------------------------------- *
 * Sync logs / audit logs
 * ---------------------------------------------------------------------- */

async function renderSyncLogs() {
  const panel = document.getElementById("tab-sync-logs");
  const logs = await client.get("/api/sync-logs?limit=100");
  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h2>Sync Logs</h2></div>
      <table>
        <thead><tr><th>Timestamp</th><th>Job</th><th>Name</th><th>Status</th><th>Items</th><th>Chunks</th><th>ms</th><th>Error</th></tr></thead>
        <tbody>
          ${logs.length ? logs.map(logRow).join("") : '<tr><td colspan="8" class="empty">No log entries yet.</td></tr>'}
        </tbody>
      </table>
    </div>`;
}

function logRow(l) {
  const cls = l.status === "SUCCESS" ? "status-ok" : l.status === "PARTIAL" ? "status-partial" : "status-failed";
  return `<tr>
    <td>${escapeHtml(l.timestamp)}</td>
    <td>${escapeHtml(l.job_type)}</td>
    <td>${escapeHtml(l.job_name)}</td>
    <td class="${cls}">${escapeHtml(l.status)}</td>
    <td>${l.items_processed}</td>
    <td>${l.chunks_sent}</td>
    <td>${l.duration_ms}</td>
    <td>${escapeHtml(l.error_message || "")}</td>
  </tr>`;
}

async function renderAuditLogs() {
  const panel = document.getElementById("tab-audit-logs");
  if (!me.is_master) {
    panel.innerHTML = '<div class="panel empty">Audit logs are visible to the Master key only.</div>';
    return;
  }
  const logs = await client.get("/api/audit-logs?limit=100");
  panel.innerHTML = `
    <div class="panel">
      <div class="panel-header"><h2>Audit Logs</h2></div>
      <table>
        <thead><tr><th>Timestamp</th><th>Actor</th><th>Client IP</th><th>Action</th><th>Target</th></tr></thead>
        <tbody>
          ${logs.length ? logs.map(auditRow).join("") : '<tr><td colspan="5" class="empty">No audit entries yet.</td></tr>'}
        </tbody>
      </table>
    </div>`;
}

function auditRow(a) {
  return `<tr>
    <td>${escapeHtml(a.timestamp)}</td>
    <td>${escapeHtml(a.api_key_name || "")} <span class="mono">${escapeHtml(a.api_key_prefix || "")}</span></td>
    <td class="mono">${escapeHtml(a.client_ip || "")}</td>
    <td>${escapeHtml(a.action)}</td>
    <td>${escapeHtml(a.target_resource || "")}</td>
  </tr>`;
}

/* ---------------------------------------------------------------------- *
 * Shared row actions
 * ---------------------------------------------------------------------- */

async function deleteResource(path, tab) {
  if (!confirm("Delete this resource? This cannot be undone.")) return;
  try {
    await client.del(path);
    toast("Deleted", "ok");
    await loadTab(tab);
  } catch (err) {
    toast("Delete failed: " + err.message, "err");
  }
}

async function triggerResource(path) {
  try {
    const result = await client.post(path);
    toast(`Triggered: ${result.status} — ${result.items_processed} items, ${result.chunks_sent} chunks`, result.status === "FAILED" ? "err" : "ok");
  } catch (err) {
    toast("Trigger failed: " + err.message, "err");
  }
}
