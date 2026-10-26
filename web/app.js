"use strict";
/* Nguoi 5: UI giong Discord, giao tiep voi HTTP bridge (1a_api.md muc 2-4).
 * - Token tu GET /api/bootstrap, giu trong bo nho, khong log.
 * - Polling GET /api/events?after= moi 500ms, 1 request tai 1 thoi diem,
 *   dung next_cursor; du 100 event lay tiep ngay; 409 EVENT_CURSOR_EXPIRED
 *   -> bao mat su kien, tai lai status/users/transfers roi tiep tuc.
 * - POST doi trang thai kem X-Local-Token. Upload PUT octet-stream.
 */
let localToken = "";
let cursor = 0;
let polling = false;
let target = null; // user_id DM; null = kenh chung #general
let myId = null;
let myName = "";
let lastUsers = [];

const $ = (id) => document.getElementById(id);
const icons = () => { if (window.lucide) lucide.createIcons(); };

function showError(msg) {
  const el = $("error");
  el.hidden = !msg;
  el.textContent = msg || "";
}

async function api(method, path, body, isFile) {
  const headers = { "X-Local-Token": localToken };
  let payload;
  if (body !== undefined) {
    if (isFile) { payload = body; }
    else { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  }
  const res = await fetch(path, { method, headers, body: payload });
  const isJson = (res.headers.get("Content-Type") || "").includes("application/json");
  const data = isJson ? await res.json() : null;
  if (!res.ok) {
    const err = new Error((data && data.error && data.error.message) || ("HTTP " + res.status));
    err.code = data && data.error && data.error.code;
    err.status = res.status;
    throw err;
  }
  return data.data;
}

function setConn(state, detail) {
  $("conn-state").textContent = state;
  $("status-text").textContent = state;
  $("status-detail").textContent = detail || "";
  const pill = $("conn-pill");
  pill.className = "pill " + (state === "connected" ? "on" : (state === "connecting" || state === "disconnecting" ? "busy" : "off"));
  $("status-dot").className = "dot " + (state === "connected" ? "online" : "");
  $("me-sub").textContent =
    state === "connected" ? "Đang hoạt động" : state === "connecting" ? "Đang kết nối…" : "Ngoại tuyến";
}

function setLoggedIn(on, user) {
  $("login-screen").hidden = on;
  $("login-screen").style.display = on ? "none" : "flex";
  $("app").hidden = !on;
  if (on && user) {
    myId = user.user_id; myName = user.username;
    $("me-name").textContent = user.username;
    $("me-avatar").textContent = user.username[0].toUpperCase();
  }
  icons();
}

function targetName() {
  if (!target) return null;
  const u = lastUsers.find((x) => x.user_id === target);
  return u ? u.username : target;
}

function renderChatHead() {
  const name = target ? "@" + targetName() : "general";
  $("chat-name").textContent = name;
  $("msg-text").placeholder = target ? "Nhắn @" + targetName() : "Nhắn #general";
  $("welcome-title").textContent = target ? "Bắt đầu với " + targetName() : "Chào mừng đến với #general!";
  $("profile-name").textContent = target ? targetName() : "Kênh chung";
  $("profile-sub").textContent = target ? "@" + targetName() + " — tin nhắn riêng" : "#general — tin nhắn tới mọi người online";
  $("profile-avatar").textContent = target ? (targetName()[0] || "?").toUpperCase() : "#";
  icons();
}

function renderUsers(users) {
  lastUsers = users;
  const q = ($("dm-filter").value || "").toLowerCase();
  const ul = $("users");
  ul.innerHTML = "";
  $("users-count").textContent = users.length;
  for (const u of users.filter((x) => x.username.toLowerCase().includes(q))) {
    const li = document.createElement("li");
    if (u.user_id === target) li.classList.add("active");
    const av = document.createElement("div");
    av.className = "avatar"; av.textContent = u.username[0].toUpperCase();
    const tx = document.createElement("div");
    const nm = document.createElement("div"); nm.textContent = u.username;
    const sm = document.createElement("small"); sm.textContent = u.user_id;
    tx.append(nm, sm);
    li.append(av, tx);
    li.onclick = () => { target = u.user_id; showError(""); renderUsers(lastUsers); renderChatHead(); };
    ul.appendChild(li);
  }
  icons();
}

function addMessage(from, to, text, when) {
  const q = ($("msg-filter").value || "").toLowerCase();
  if (q && !(from + " " + text).toLowerCase().includes(q)) return;
  const li = document.createElement("li");
  const av = document.createElement("div");
  av.className = "avatar"; av.textContent = (from[0] || "?").toUpperCase();
  const body = document.createElement("div");
  body.className = "body";
  const head = document.createElement("div");
  const b = document.createElement("b"); b.textContent = from + (to ? " → " + to : "");
  const sm = document.createElement("small"); sm.textContent = when || "";
  head.append(b, sm);
  const p = document.createElement("p"); p.textContent = text;
  body.append(head, p);
  li.append(av, body);
  $("messages").appendChild(li);
  li.scrollIntoView({ block: "end" });
}

function addSys(text) {
  const li = document.createElement("li");
  li.className = "sys";
  li.textContent = text;
  $("messages").appendChild(li);
}

function upsertTransfer(t) {
  let li = document.querySelector('li[data-tid="' + t.transfer_id + '"]');
  if (!li) {
    li = document.createElement("li");
    li.dataset.tid = t.transfer_id;
    $("transfers").appendChild(li);
  }
  const pct = t.progress || 0;
  li.innerHTML = "";
  li.append(document.createTextNode(
    (t.direction === "incoming" ? "Nhận: " : "Gửi: ") + t.filename + " (" + t.size + "B) — " +
    t.status + " " + pct + "%" + (t.error_code ? " · lỗi:" + t.error_code : "")));
  const bar = document.createElement("progress");
  bar.max = 100; bar.value = pct;
  li.appendChild(bar);
  const row = document.createElement("div");
  if (t.direction === "incoming" && t.status === "offered") {
    const ok = document.createElement("button");
    ok.textContent = "Nhận";
    ok.onclick = async () => { try { await api("POST", "/api/files/" + t.transfer_id + "/accept", {}); } catch (e) { showError(e.message); } };
    const no = document.createElement("button");
    no.textContent = "Từ chối"; no.className = "ghost";
    no.onclick = async () => { try { await api("POST", "/api/files/" + t.transfer_id + "/reject", { reason: "Không nhận tệp" }); } catch (e) { showError(e.message); } };
    row.append(ok, no);
  }
  if (t.direction === "incoming" && t.status === "completed") {
    const a = document.createElement("a");
    a.href = "/api/files/" + t.transfer_id + "/download";
    a.textContent = "Tải về";
    row.appendChild(a);
  }
  li.appendChild(row);
}

function handleEvent(ev) {
  const d = ev.data;
  switch (ev.type) {
    case "connection_changed":
      setConn(d.state, d.error_code ? "Lỗi: " + d.error_code : d.user ? "Xin chào " + d.user.username + "!" : "");
      setLoggedIn(d.state === "connected", d.user || (myId ? { user_id: myId, username: myName } : null));
      if (d.state === "connected" && d.user) setLoggedIn(true, d.user);
      if (d.error_code) showError("Kết nối: " + d.error_code);
      else if (d.state === "connected") showError("");
      renderChatHead();
      break;
    case "users_updated": renderUsers(d.users); renderChatHead(); break;
    case "message_received": {
      const toName = d.to ? (d.to === myId ? myName + " (bạn)" : d.to) : null;
      addMessage(d.from, toName, d.text, (d.sent_at || "").replace("T", " ").slice(0, 16));
      break;
    }
    case "message_status":
      if (d.status === "failed") addSys("Gửi thất bại (" + (d.error_code || "?") + ")");
      break;
    case "file_offer":
      upsertTransfer({ transfer_id: d.transfer_id, direction: "incoming", filename: d.filename, size: d.size, status: "offered", progress: 0 });
      addSys("Tệp đến từ " + d.from + ": " + d.filename + " — xem cột phải để Nhận/Từ chối.");
      break;
    case "file_status":
    case "file_progress":
    case "file_completed": refreshTransfers(); break;
    case "error": showError(d.code + ": " + d.message); break;
  }
}

async function refreshTransfers() {
  try {
    const t = await api("GET", "/api/files");
    for (const x of t.transfers) upsertTransfer(x);
  } catch (e) { /* giu UI cu khi loi mang */ }
}

async function pollOnce() {
  if (polling) return;
  polling = true;
  try {
    const t = await api("GET", "/api/events?after=" + cursor);
    for (const ev of t.events) handleEvent(ev);
    cursor = t.next_cursor;
    if (t.events.length >= 100) setTimeout(pollOnce, 0);
  } catch (e) {
    if (e.code === "EVENT_CURSOR_EXPIRED" || e.status === 409) {
      showError("Có thể mất sự kiện, đang tải lại...");
      try {
        const s = await api("GET", "/api/status");
        setConn(s.state, "");
        renderUsers((await api("GET", "/api/users")).users);
        await refreshTransfers();
        // cursor moi lay tu lan poll ke tiep; giu polling tiep tuc
      } catch (_) { /* bo qua */ }
    }
  } finally { polling = false; }
}

async function sendText() {
  const text = $("msg-text").value;
  if (!text.trim()) return;
  if (new TextEncoder().encode(text).length > 800) { showError("Tin nhắn vượt quá 800 byte UTF-8"); return; }
  try {
    await api("POST", "/api/messages", { to: target, text });
    $("msg-text").value = "";
    showError("");
  } catch (err) { showError(err.message); }
}

async function sendFile(file) {
  if (!target) { showError("V1 chỉ gửi tệp riêng: hãy chọn một bạn trong danh sách online"); return; }
  if (file.size > 100 * 1024 * 1024) { showError("Tệp vượt quá 100 MiB"); return; }
  try {
    const offer = await api("POST", "/api/files/offers", { to: target, filename: file.name, size: file.size });
    await api("PUT", "/api/files/" + offer.transfer_id + "/content", file, true);
    await refreshTransfers();
    showError("");
  } catch (err) { showError(err.message); }
}

async function init() {
  icons();
  const boot = await fetch("/api/bootstrap").then((r) => r.json());
  localToken = boot.data.local_token;
  const st = await api("GET", "/api/status");
  setConn(st.state, "");
  if (st.state === "connected" && st.user) {
    setLoggedIn(true, st.user);
    try { renderUsers((await api("GET", "/api/users")).users); } catch (_) {}
    await refreshTransfers();
  } else {
    setLoggedIn(false, null);
  }
  renderChatHead();
  setInterval(pollOnce, 500);
  pollOnce();

  $("login-form").onsubmit = async (e) => {
    e.preventDefault();
    const le = $("login-error");
    le.hidden = true;
    try {
      await api("POST", "/api/login", { username: $("username").value, password: $("password").value });
      $("password").value = "";
    } catch (err) { le.hidden = false; le.textContent = err.message; }
  };
  $("logout-btn").onclick = async () => {
    try { await api("POST", "/api/logout", {}); } catch (e) { showError(e.message); }
  };
  $("nav-friends").onclick = () => {
    target = null; showError("");
    document.querySelectorAll(".side-nav-item").forEach((b) => b.classList.remove("active"));
    $("nav-friends").classList.add("active");
    renderUsers(lastUsers); renderChatHead();
  };
  $("dm-refresh").onclick = async () => {
    try { renderUsers((await api("GET", "/api/users")).users); } catch (e) { showError(e.message); }
  };
  $("dm-filter").oninput = () => renderUsers(lastUsers);
  $("msg-filter").oninput = () => { /* loc cho tin tiep theo */ };
  $("msg-text").addEventListener("keydown", (e) => { if (e.key === "Enter") sendText(); });

  const menu = $("attach-menu");
  $("plus-btn").onclick = () => { menu.hidden = !menu.hidden; };
  $("attach-file").onclick = () => $("file-input").click();
  $("file-input").onchange = () => {
    const f = $("file-input").files[0];
    menu.hidden = true;
    if (f) sendFile(f);
    $("file-input").value = "";
  };
}

init().catch((e) => {
  const b = $("boot-error");
  b.hidden = false; b.textContent = "Không kết nối bridge: " + e.message;
});
