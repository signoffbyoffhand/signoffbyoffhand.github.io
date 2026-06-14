/* SignOff by Offhand — produkcyjna aplikacja do zbierania zgód (wizerunek, RODO, regulaminy).
   Offline-first PWA + kopia w chmurze (E2E).
   Model kluczy: losowy klucz główny danych (DEK, AES-256) szyfruje całą bazę;
   PIN każdego konta jedynie "opakowuje" DEK (PBKDF2 -> KEK -> wrap). Dzięki temu:
   - wiele kont (admin/pracownik) z własnymi PIN-ami,
   - admin resetuje PIN bez przeszyfrowania bazy,
   - kopia w chmurze odtwarzalna PIN-em dowolnego konta. */
"use strict";

/* ===================== Narzędzia krypto ===================== */
const te = new TextEncoder(), td = new TextDecoder();
const b64 = {
  enc: (buf) => {
    const u = new Uint8Array(buf); let s = "";
    for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  },
  dec: (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer,
};
async function sha256hex(data) {
  const buf = typeof data === "string" ? te.encode(data) : data;
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function deriveKEK(pin, saltB64) {
  const base = await crypto.subtle.importKey("raw", te.encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: new Uint8Array(b64.dec(saltB64)), iterations: 310000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
const importDEK = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(JSON.stringify(obj)));
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function decryptJSON(key, pack) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(b64.dec(pack.iv)) }, key, b64.dec(pack.ct));
  return JSON.parse(td.decode(pt));
}
async function encryptBytes(key, buf) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buf);
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function decryptBytes(key, pack) {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(b64.dec(pack.iv)) }, key, b64.dec(pack.ct));
}
const uuid = () => crypto.randomUUID();
const PIN_RE = /^\d{6,}$/;
const isValidEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test((e || "").trim());

/* ===================== IndexedDB ===================== */
let dbh = null;
function openDB() {
  return new Promise((res, rej) => {
    const rq = indexedDB.open("signoff", 1);
    rq.onupgradeneeded = () => {
      const d = rq.result;
      d.createObjectStore("meta");
      d.createObjectStore("records", { keyPath: "id" });
      d.createObjectStore("outbox", { keyPath: "id" });
      d.createObjectStore("files", { keyPath: "id" });
    };
    rq.onsuccess = () => res(rq.result);
    rq.onerror = () => rej(rq.error);
  });
}
const tx = (store, mode, fn) => new Promise((res, rej) => {
  const t = dbh.transaction(store, mode), s = t.objectStore(store);
  const out = fn(s);
  t.oncomplete = () => res(out && out.result !== undefined ? out.result : out);
  t.onerror = () => rej(t.error);
});
const storeGet = (store, k) => new Promise((res, rej) => {
  const rq = dbh.transaction(store).objectStore(store).get(k);
  rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
});
const metaGet = (k) => storeGet("meta", k);
const metaSet = (k, v) => tx("meta", "readwrite", s => s.put(v, k));
const getAll = (store) => new Promise((res, rej) => {
  const rq = dbh.transaction(store).objectStore(store).getAll();
  rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
});

/* ===================== Stan ===================== */
const S = {
  key: null,       // DEK jako CryptoKey
  dekRaw: null,    // DEK surowy (do tworzenia kont / resetów) — tylko w pamięci
  user: null,      // zalogowane konto
  config: null,    // jawne: deviceId, accounts[], chainHead, lastSync
  vault: null,     // szyfrowane DEK: producer, email, projects[], sync{}
  records: [],
  wizard: null,
  lockTimer: null,
  syncTimer: null,
};
const $ = (id) => document.getElementById(id);
const views = ["view-setup", "view-lock", "view-home", "view-wizard", "view-detail", "view-settings"];
function show(view) { views.forEach(v => $(v).hidden = v !== view); window.scrollTo(0, 0); }
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const isAdmin = () => S.user && S.user.role === "admin";
const roleLabel = (r) => r === "admin" ? "administrator" : r === "inne" ? "inne" : "pracownik";
function activeProject() { return allowedProjects().find(p => p.id === S.vault.activeProjectId) || allowedProjects()[0]; }
function allowedProjects() {
  if (isAdmin()) return S.vault.projects;
  return S.vault.projects.filter(p => !(p.allowedUserIds || []).length || p.allowedUserIds.includes(S.user.id));
}
async function saveVault() { await metaSet("vault", await encryptJSON(S.key, S.vault)); scheduleSync(); }
async function saveConfig() { await metaSet("config", S.config); }

/* ===================== Szablon zgody ===================== */
const TEMPLATE_VERSION = "3.0-PL";
function defaultClause(cfg, proj, p) {
  const who = p.isMinor
    ? `Ja, ${p.gfirst} ${p.glast}, działając jako rodzic/opiekun prawny małoletniego(-iej) ${p.first} ${p.last},`
    : `Ja, ${p.first} ${p.last},`;
  const today = new Date().toLocaleDateString("pl-PL");
  return (
`ZEZWOLENIE NA ROZPOWSZECHNIANIE WIZERUNKU (art. 81 pr. aut.)

${who} wyrażam zgodę na nieodpłatne utrwalenie i rozpowszechnianie ${p.isMinor ? "wizerunku oraz wypowiedzi małoletniego(-iej)" : "mojego wizerunku oraz moich wypowiedzi"} zarejestrowanych w dniu ${today} przez ${cfg.producer} w ramach projektu „${proj.name}”, na wszystkich znanych polach eksploatacji, bez ograniczeń terytorialnych i czasowych, w tym w szczególności: w kinach, telewizji, na platformach streamingowych (VOD), w internecie, na festiwalach oraz we fragmentach wykorzystywanych w zwiastunach — wraz z prawem do udzielania sublicencji i przeniesienia praw na dystrybutorów.

Zezwolenie obejmuje montaż, kadrowanie i zestawianie zarejestrowanego materiału z innymi materiałami, z poszanowaniem dóbr osobistych. Zezwolenie udzielane jest na rzecz ${cfg.producer} oraz jego następców prawnych.`);
}
function rodoClause(cfg) {
  return (
`KLAUZULA INFORMACYJNA RODO (art. 13 RODO)

1. Administratorem danych osobowych (w tym wizerunku) jest ${cfg.producer}.
2. Dane przetwarzane są w celu realizacji, promocji i eksploatacji projektu — na podstawie art. 6 ust. 1 lit. a RODO (zgoda) oraz art. 6 ust. 1 lit. f RODO (prawnie uzasadniony interes administratora).
3. Dane mogą być przekazywane koproducentom, dystrybutorom, ubezpieczycielom i platformom emisyjnym — wyłącznie w zakresie niezbędnym do eksploatacji projektu.
4. Dane będą przechowywane przez okres eksploatacji projektu, a dokument zgody — dodatkowo przez okres przedawnienia roszczeń.
5. Przysługuje Pani/Panu prawo dostępu do danych, ich sprostowania, usunięcia, ograniczenia przetwarzania, sprzeciwu oraz skargi do Prezesa UODO.
6. Zgodę na przetwarzanie danych można cofnąć w każdej chwili ze skutkiem na przyszłość — nie wpływa to na zgodność z prawem przetwarzania dokonanego przed cofnięciem ani na nabyte zgodnie z prawem zezwolenie na rozpowszechnianie wizerunku w już wyprodukowanym materiale (art. 81 pr. aut. stanowi odrębną podstawę).
7. Podanie danych jest dobrowolne, lecz niezbędne do udziału w projekcie.

INFORMACJA O PODPISIE ELEKTRONICZNYM

Dokument podpisywany jest podpisem elektronicznym w formie dokumentowej (art. 77² Kodeksu cywilnego). Zapisywany jest wyłącznie obraz podpisu — aplikacja nie rejestruje danych biometrycznych. Dokument otrzymuje znacznik czasu, sumę kontrolną SHA-256 oraz kartę dowodową (audit trail). Kopia dokumentu zostanie przekazana podpisującemu.`);
}
function consentText(cfg, proj, p) {
  const body = (proj.customText || "").trim() || defaultClause(cfg, proj, p);
  return body + "\n\n" + rodoClause(cfg);
}

/* ===================== Audit trail ===================== */
function auditEvent(w, type, detail) { w.audit.push({ ts: new Date().toISOString(), type, detail: detail || "" }); }
function deviceInfo() {
  return {
    ua: navigator.userAgent, platform: navigator.platform || "",
    lang: navigator.language, screen: `${screen.width}x${screen.height}@${window.devicePixelRatio}`,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
  };
}
function tryGeolocate(w) {
  if (!navigator.geolocation) return;
  navigator.geolocation.getCurrentPosition(
    pos => { w.geo = { lat: +pos.coords.latitude.toFixed(5), lon: +pos.coords.longitude.toFixed(5), acc: Math.round(pos.coords.accuracy) }; auditEvent(w, "geolokalizacja", `${w.geo.lat}, ${w.geo.lon} (±${w.geo.acc} m)`); },
    () => { auditEvent(w, "geolokalizacja", "niedostępna / brak zgody na lokalizację"); },
    { timeout: 6000, maximumAge: 60000 });
}

/* ===================== Inicjalizacja ===================== */
/* ===================== Podpowiedzi (hover na PC, długie przytrzymanie na dotyku) ===================== */
function initHelp() {
  const tip = document.createElement("div");
  tip.className = "help-tip"; tip.hidden = true;
  document.body.appendChild(tip);
  document.querySelectorAll("[data-help]").forEach(el => { if (!el.title) el.title = el.dataset.help; });
  let timer = null, hideTimer = null;
  const showTip = (el) => {
    tip.textContent = el.dataset.help;
    tip.hidden = false;
    const r = el.getBoundingClientRect();
    tip.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 290)) + "px";
    tip.style.top = (r.bottom + 8) + "px";
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => { tip.hidden = true; }, 5000);
  };
  document.addEventListener("touchstart", (e) => {
    const el = e.target.closest("[data-help]");
    if (!el) return;
    timer = setTimeout(() => showTip(el), 550);
  }, { passive: true });
  ["touchend", "touchmove", "touchcancel"].forEach(ev =>
    document.addEventListener(ev, () => clearTimeout(timer), { passive: true }));
}

/* Automatyczna aktualizacja PWA: gdy jest internet, nowa wersja pobiera się w tle.
   Nie przerywa pracy — pokazuje pasek „Odśwież", a przy ponownym otwarciu appki wchodzi sama. */
function setupServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  let refreshing = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (refreshing) return; refreshing = true; location.reload();
  });
  navigator.serviceWorker.register("sw.js", { updateViaCache: "none" }).then(reg => {
    const check = () => { if (navigator.onLine) reg.update().catch(() => {}); };
    check();
    setInterval(check, 30 * 60 * 1000);                       // co 30 min
    window.addEventListener("online", check);                  // od razu po odzyskaniu sieci
    document.addEventListener("visibilitychange", () => { if (!document.hidden) check(); });
    if (reg.waiting && navigator.serviceWorker.controller) showUpdateBanner(reg.waiting);
    reg.addEventListener("updatefound", () => {
      const nw = reg.installing;
      if (!nw) return;
      nw.addEventListener("statechange", () => {
        if (nw.state === "installed" && navigator.serviceWorker.controller) showUpdateBanner(nw);
      });
    });
  }).catch(() => {});
}
function showUpdateBanner(worker) {
  if (document.getElementById("update-banner")) return;
  const bar = document.createElement("div");
  bar.id = "update-banner";
  bar.innerHTML = `<span>✨ Dostępna nowa wersja aplikacji</span><button class="btn" id="btn-update">Odśwież</button>`;
  document.body.appendChild(bar);
  $("btn-update").addEventListener("click", () => {
    $("btn-update").textContent = "Aktualizuję…";
    worker.postMessage({ type: "SKIP_WAITING" });
  });
}

async function boot() {
  initHelp();
  dbh = await openDB();
  setupServiceWorker();
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
  S.config = await metaGet("config") || null;
  updateNetBadge();
  window.addEventListener("online", () => { updateNetBadge(); scheduleSync(); flushOutbox(); });
  window.addEventListener("offline", updateNetBadge);
  ["click", "keydown", "pointerdown"].forEach(ev => document.addEventListener(ev, resetLockTimer, { passive: true }));
  if (!S.config) show("view-setup"); else enterLogin();
}
function updateNetBadge() {
  const b = $("net-status");
  b.textContent = navigator.onLine ? "online" : "offline";
  b.className = "badge " + (navigator.onLine ? "online" : "offline");
}
function resetLockTimer() {
  if (!S.key) return;
  clearTimeout(S.lockTimer);
  S.lockTimer = setTimeout(lock, 5 * 60 * 1000);
}
function lock() {
  S.key = null; S.dekRaw = null; S.vault = null; S.records = []; S.wizard = null; S.user = null;
  clearTimeout(S.lockTimer);
  enterLogin();
}

/* --- pierwsze uruchomienie: dwa konta administratorów --- */
$("btn-setup").addEventListener("click", async () => {
  const producer = $("setup-producer").value.trim();
  const project = $("setup-project").value.trim();
  const ph = $("setup-pin-h").value, ph2 = $("setup-pin-h2").value;
  const pm = $("setup-pin-m").value, pm2 = $("setup-pin-m2").value;
  const err = $("setup-error"); err.hidden = true;
  const fail = (m) => { err.textContent = m; err.hidden = false; };
  if (!producer || !project) return fail("Podaj nazwę firmy i projektu.");
  if (!PIN_RE.test(ph)) return fail("PIN Hanny Nobis: min. 6 cyfr.");
  if (ph !== ph2) return fail("PIN-y Hanny Nobis nie są zgodne.");
  if (!PIN_RE.test(pm)) return fail("PIN Marka Żaka: min. 6 cyfr.");
  if (pm !== pm2) return fail("PIN-y Marka Żaka nie są zgodne.");
  if (ph === pm) return fail("PIN-y administratorów muszą się różnić.");

  const dekRaw = crypto.getRandomValues(new Uint8Array(32)).buffer;
  const mkAccount = async (name, role, pin) => {
    const salt = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
    const kek = await deriveKEK(pin, salt);
    return { id: uuid(), name, role, salt, wrap: await encryptBytes(kek, dekRaw), fails: 0, lockUntil: 0, active: true, createdAt: new Date().toISOString() };
  };
  const accounts = [
    await mkAccount("Hanna Nobis", "admin", ph),
    await mkAccount("Marek Żak", "admin", pm),
  ];
  S.config = { v: 3, deviceId: uuid(), deviceName: producer.slice(0, 40) + " · " + (navigator.platform || "urządzenie"), accounts, chainHead: "GENESIS", lastSync: null };
  await saveConfig();
  S.dekRaw = dekRaw;
  S.key = await importDEK(dekRaw);
  S.user = accounts[0];
  const pid = uuid();
  S.vault = { producer, email: "", projects: [{ id: pid, name: project, customText: "", files: [], allowedUserIds: [] }], activeProjectId: pid, sync: { url: "", key: "", auto: true } };
  await saveVault();
  enterHome();
});

/* --- logowanie kontem --- */
let accSelected = null;
function enterLogin() {
  accSelected = null;
  $("lock-pin").value = "";
  $("lock-error").hidden = true;
  $("lock-title").textContent = "Zaloguj się";
  const box = $("account-buttons");
  box.innerHTML = "";
  for (const acc of S.config.accounts.filter(a => a.active)) {
    const b = document.createElement("button");
    b.className = "btn op-btn";
    b.innerHTML = `${esc(acc.name)} <span class="op-role">${roleLabel(acc.role)}</span>`;
    b.addEventListener("click", () => {
      accSelected = acc;
      [...box.children].forEach(x => x.classList.remove("primary"));
      b.classList.add("primary");
      $("lock-pin").focus();
    });
    box.appendChild(b);
  }
  show("view-lock");
}
async function login() {
  const err = $("lock-error"); err.hidden = true;
  if (!accSelected) { err.textContent = "Wybierz konto."; err.hidden = false; return; }
  const acc = accSelected;
  if (acc.lockUntil && Date.now() < acc.lockUntil) {
    $("lock-title").textContent = "Konto zablokowane";
    err.textContent = `Zbyt wiele błędnych prób. Spróbuj za ${Math.ceil((acc.lockUntil - Date.now()) / 1000)} s.`;
    err.hidden = false; return;
  }
  try {
    const kek = await deriveKEK($("lock-pin").value, acc.salt);
    const dekRaw = await decryptBytes(kek, acc.wrap); // AES-GCM uwierzytelnia — zły PIN = wyjątek
    S.dekRaw = dekRaw;
    S.key = await importDEK(dekRaw);
    S.user = acc;
    acc.fails = 0; acc.lockUntil = 0;
    await saveConfig();
    S.vault = await decryptJSON(S.key, await metaGet("vault"));
    await loadRecords();
    enterHome();
  } catch {
    acc.fails = (acc.fails || 0) + 1;
    $("lock-title").textContent = "Aplikacja zablokowana";
    if (acc.fails >= 5) {
      acc.lockUntil = Date.now() + 30000 * Math.pow(2, acc.fails - 5);
      err.textContent = `Nieprawidłowy PIN. Konto zablokowane na ${Math.round(30 * Math.pow(2, acc.fails - 5))} s.`;
    } else {
      err.textContent = `Nieprawidłowy PIN (próba ${acc.fails}/5 przed blokadą konta).`;
    }
    await saveConfig();
    err.hidden = false;
  }
}
$("btn-unlock").addEventListener("click", login);
$("lock-pin").addEventListener("keydown", e => { if (e.key === "Enter") login(); });

async function loadRecords() {
  const rows = await getAll("records");
  S.records = [];
  for (const row of rows) {
    try {
      const rec = await decryptJSON(S.key, row.pack);
      rec._chain = row.chain;
      if (!rec.projectId) rec.projectId = S.vault.projects[0].id;
      S.records.push(rec);
    }
    catch { S.records.push({ id: row.id, corrupted: true, _chain: row.chain }); }
  }
  S.records.sort((a, b) => (a.createdAt || "").localeCompare(b.createdAt || ""));
}

/* ===================== Role w UI ===================== */
function applyRole() {
  document.querySelectorAll(".admin-only").forEach(el => { el.style.display = isAdmin() ? "" : "none"; });
  const ub = $("user-badge");
  ub.textContent = S.user.name + " · " + roleLabel(S.user.role);
}

/* ===================== Ekran główny ===================== */
function enterHome() {
  resetLockTimer();
  applyRole();
  const projs = allowedProjects();
  if (!projs.length) { alert("Brak projektów przydzielonych temu kontu — skontaktuj się z administratorem."); lock(); return; }
  if (!projs.find(p => p.id === S.vault.activeProjectId)) S.vault.activeProjectId = projs[0].id;
  $("project-select").innerHTML = projs.map(p => `<option value="${p.id}" ${p.id === S.vault.activeProjectId ? "selected" : ""}>${esc(p.name)}</option>`).join("");
  $("home-producer").textContent = S.vault.producer;
  renderStats(); renderList($("search").value);
  $("verify-result").hidden = true;
  updateSyncBadge();
  flushOutbox();
  show("view-home");
}
$("project-select").addEventListener("change", async (e) => {
  S.vault.activeProjectId = e.target.value;
  await saveVault();
  renderStats(); renderList($("search").value);
});
function projectRecords() {
  const pid = S.vault.activeProjectId;
  return S.records.filter(r => r.corrupted || r.projectId === pid);
}
function renderStats() {
  const rs = projectRecords().filter(r => !r.corrupted);
  $("home-stats").innerHTML =
    `<div class="stat"><b>${rs.length}</b><span>zgód w projekcie</span></div>` +
    `<div class="stat"><b>${rs.filter(r => r.status === "active").length}</b><span>aktywnych</span></div>` +
    `<div class="stat"><b>${rs.filter(r => r.status !== "active").length}</b><span>cofniętych (RODO)</span></div>` +
    `<div class="stat"><b>${S.records.filter(r => !r.corrupted).length}</b><span>łącznie (wszystkie projekty)</span></div>`;
}
function renderList(filter) {
  const list = $("records-list");
  const f = (filter || "").toLowerCase();
  const items = projectRecords().filter(r => !f || (!r.corrupted && (`${r.person.first} ${r.person.last}`.toLowerCase().includes(f))));
  if (!items.length) { list.innerHTML = `<div class="empty">Brak zgód${f ? " dla tego filtra" : " w tym projekcie"}. Dotknij „＋ Nowa zgoda”.</div>`; return; }
  list.innerHTML = "";
  for (const r of [...items].reverse()) {
    const div = document.createElement("div");
    div.className = "record";
    if (r.corrupted) {
      div.innerHTML = `<div class="who"><b>⚠ Rekord nieodczytywalny</b><span>${esc(r.id)}</span></div><span class="badge revoked">błąd</span>`;
    } else {
      const d = new Date(r.createdAt).toLocaleString("pl-PL");
      const marks = [
        `<span class="badge ok">art. 81 ✓</span>`,
        r.status === "active" ? `<span class="badge ok">RODO ✓</span>` : `<span class="badge revoked">RODO cofnięta</span>`,
        r.person.isMinor ? `<span class="badge planned">małoletni</span>` : "",
        (r.attachments || []).length ? `<span class="badge planned">📎 ${r.attachments.length}</span>` : "",
        r.photo ? `<span class="badge planned">📷</span>` : "",
      ].join("");
      div.innerHTML = `<div class="who"><b>${esc(r.person.first)} ${esc(r.person.last)}</b><span>${esc(r.person.role || "—")} · ${d}${r.operator ? " · zebrał(a): " + esc(r.operator) : ""}</span></div><div class="marks">${marks}</div>`;
      div.addEventListener("click", () => showDetail(r.id));
    }
    list.appendChild(div);
  }
}
$("search").addEventListener("input", e => renderList(e.target.value));
$("btn-lock").addEventListener("click", lock);
$("btn-settings").addEventListener("click", enterSettings);
$("btn-new").addEventListener("click", startWizard);

/* --- weryfikacja łańcucha integralności --- */
$("btn-verify").addEventListener("click", async () => {
  const out = $("verify-result");
  out.hidden = false; out.textContent = "Weryfikuję…";
  const rows = (await getAll("records")).sort((a, b) => a.seq - b.seq);
  let prev = "GENESIS", okCount = 0, bad = null;
  for (const row of rows) {
    const expect = await sha256hex(prev + row.recordHash);
    if (expect !== row.chain) { bad = row.id; break; }
    prev = row.chain; okCount++;
  }
  if (bad) { out.textContent = `🛑 NARUSZENIE INTEGRALNOŚCI przy rekordzie ${bad} — dane były modyfikowane poza aplikacją!`; out.style.color = "var(--bad)"; }
  else if (prev !== (S.config.chainHead || "GENESIS")) { out.textContent = "🛑 Czoło łańcucha niezgodne z konfiguracją — możliwe usunięcie rekordów."; out.style.color = "var(--bad)"; }
  else { out.textContent = `✅ Integralność potwierdzona: ${okCount} rekordów, łańcuch SHA-256 spójny.`; out.style.color = "var(--good)"; }
});

/* ===================== Kopia: plik + chmura ===================== */
async function buildBackup() {
  const [records, files, outbox, vaultPack] = await Promise.all([getAll("records"), getAll("files"), getAll("outbox"), metaGet("vault")]);
  return { app: "signoff", v: 3, exportedAt: new Date().toISOString(), config: S.config, vault: vaultPack, records, files, outbox };
}
async function applyBackup(data) {
  if (data.app !== "signoff") throw new Error("To nie jest kopia SignOff (kopie starego prototypu są niezgodne).");
  await tx("records", "readwrite", s => s.clear());
  await tx("files", "readwrite", s => s.clear());
  await tx("outbox", "readwrite", s => s.clear());
  for (const r of data.records) await tx("records", "readwrite", s => s.put(r));
  for (const f of (data.files || [])) await tx("files", "readwrite", s => s.put(f));
  for (const o of (data.outbox || [])) await tx("outbox", "readwrite", s => s.put(o));
  await metaSet("config", data.config);
  await metaSet("vault", data.vault);
}
async function exportBackup() {
  const blob = new Blob([JSON.stringify(await buildBackup())], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `signoff-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
$("btn-export").addEventListener("click", exportBackup);
$("btn-export2").addEventListener("click", exportBackup);
$("btn-import").addEventListener("click", () => $("import-file").click());
$("import-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    if (!confirm(`Przywrócić kopię z ${new Date(data.exportedAt).toLocaleString("pl-PL")}?\n\nUWAGA: zastąpi WSZYSTKIE obecne dane (${(data.records || []).length} rekordów w kopii). Zalogujesz się PIN-em konta z chwili wykonania kopii.`)) return;
    await applyBackup(data);
    alert("Kopia przywrócona. Zaloguj się ponownie.");
    location.reload();
  } catch (ex) { alert("Błąd importu: " + ex.message); }
  finally { e.target.value = ""; }
});

/* --- synchronizacja z chmurą (E2E — wysyłamy wyłącznie zaszyfrowane pakiety) --- */
function syncCfg() { return (S.vault && S.vault.sync) || { url: "", key: "", auto: true }; }
function updateSyncBadge(msg) {
  const b = $("sync-badge");
  const c = syncCfg();
  if (msg) { b.textContent = "☁ " + msg; return; }
  if (!c.url) { b.textContent = "☁ wyłączona"; b.className = "badge planned"; return; }
  if (S.config.lastSync) { b.textContent = "☁ " + new Date(S.config.lastSync).toLocaleTimeString("pl-PL", { hour: "2-digit", minute: "2-digit" }); b.className = "badge online"; }
  else { b.textContent = "☁ oczekuje"; b.className = "badge offline"; }
}
async function syncPush(manual) {
  const c = syncCfg();
  if (!c.url || !c.key) { if (manual) alert("Skonfiguruj adres serwera i klucz synchronizacji."); return false; }
  if (!navigator.onLine) { updateSyncBadge("offline — wyśle po połączeniu"); return false; }
  try {
    updateSyncBadge("wysyłanie…");
    const payload = await buildBackup();
    const resp = await fetch(c.url.replace(/\/+$/, "") + "/api/sync", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Sync-Key": c.key },
      body: JSON.stringify({ deviceId: S.config.deviceId, deviceName: S.config.deviceName, payload }),
    });
    const out = await resp.json();
    if (!resp.ok) throw new Error(out.error || resp.status);
    S.config.lastSync = out.updatedAt;
    await saveConfig();
    updateSyncBadge();
    if (manual) $("sync-status").textContent = "✅ Zsynchronizowano: " + new Date(out.updatedAt).toLocaleString("pl-PL");
    return true;
  } catch (e) {
    updateSyncBadge("błąd");
    if (manual) $("sync-status").textContent = "🛑 Błąd synchronizacji: " + e.message;
    return false;
  }
}
function scheduleSync() {
  const c = syncCfg();
  if (!c.url || !c.auto || !S.key) return;
  clearTimeout(S.syncTimer);
  S.syncTimer = setTimeout(() => syncPush(false), 2500);
}
$("btn-sync-save").addEventListener("click", async () => {
  S.vault.sync = { url: $("sync-url").value.trim(), key: $("sync-key").value.trim(), auto: $("sync-auto").checked, autoEmail: $("sync-autoemail").checked };
  await metaSet("vault", await encryptJSON(S.key, S.vault));
  $("sync-status").textContent = "Testuję połączenie…";
  const ok = await syncPush(true);
  if (ok) updateSyncBadge();
});
$("btn-sync-now").addEventListener("click", () => syncPush(true));
$("btn-sync-restore").addEventListener("click", async () => {
  const c = syncCfg();
  const box = $("restore-list");
  if (!c.url || !c.key) { box.innerHTML = '<p class="error">Najpierw skonfiguruj serwer i klucz.</p>'; return; }
  box.innerHTML = "Pobieram listę kopii…";
  try {
    const resp = await fetch(c.url.replace(/\/+$/, "") + "/api/devices", { headers: { "X-Sync-Key": c.key } });
    const out = await resp.json();
    if (!resp.ok) throw new Error(out.error || resp.status);
    if (!out.devices.length) { box.innerHTML = '<p class="tiny muted">Brak kopii na serwerze.</p>'; return; }
    box.innerHTML = "";
    for (const d of out.devices) {
      const row = document.createElement("div");
      row.className = "attach-row";
      row.innerHTML = `<div class="attach-info">💾 <b>${esc(d.deviceName || d.deviceId)}</b> <span class="tiny muted">ostatnia kopia: ${new Date(d.updatedAt).toLocaleString("pl-PL")}${d.deviceId === S.config.deviceId ? " · (to urządzenie)" : ""}</span></div><button class="btn">⬇ Przywróć</button>`;
      row.querySelector("button").addEventListener("click", async () => {
        if (!confirm(`Przywrócić kopię „${d.deviceName}” z ${new Date(d.updatedAt).toLocaleString("pl-PL")}?\n\nZastąpi WSZYSTKIE dane na tym urządzeniu.`)) return;
        const r2 = await fetch(c.url.replace(/\/+$/, "") + "/api/sync?device=" + encodeURIComponent(d.deviceId), { headers: { "X-Sync-Key": c.key } });
        const data = await r2.json();
        if (!r2.ok) { alert("Błąd: " + (data.error || r2.status)); return; }
        await applyBackup(data.payload);
        alert("Kopia przywrócona. Zaloguj się ponownie.");
        location.reload();
      });
      box.appendChild(row);
    }
  } catch (e) { box.innerHTML = `<p class="error">Błąd: ${esc(e.message)}</p>`; }
});

/* ===================== Pliki projektu (PDF do podpisu) ===================== */
async function addFileToProject(proj, file) {
  if (file.type !== "application/pdf") throw new Error("Obsługiwane są pliki PDF.");
  if (file.size > 15 * 1024 * 1024) throw new Error("Plik przekracza 15 MB.");
  const buf = await file.arrayBuffer();
  const hash = await sha256hex(buf);
  const id = uuid();
  const pack = await encryptBytes(S.key, buf);
  await tx("files", "readwrite", s => s.put({ id, pack }));
  proj.files.push({ id, name: file.name, size: file.size, hash, addedAt: new Date().toISOString() });
  await saveVault();
}
async function openFile(fileMeta) {
  const row = await storeGet("files", fileMeta.id);
  if (!row) { alert("Nie znaleziono pliku w magazynie."); return; }
  const buf = await decryptBytes(S.key, row.pack);
  const url = URL.createObjectURL(new Blob([buf], { type: "application/pdf" }));
  window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

/* ===================== Kreator ===================== */
const STEPS = 6;
function startWizard() {
  const proj = activeProject();
  S.wizard = {
    id: uuid(), audit: [], device: deviceInfo(), geo: null,
    signature: null, photo: null, startedAt: new Date().toISOString(),
    projectId: proj.id, projectName: proj.name,
    attachChecks: {},
  };
  auditEvent(S.wizard, "start", `otwarto formularz zgody (projekt: ${proj.name}, zbiera: ${S.user.name} [${S.user.role}])`);
  tryGeolocate(S.wizard);
  $("wizard-project-label").textContent = `Projekt: ${proj.name} · Zbiera: ${S.user.name}`;
  ["f-first", "f-last", "f-email", "f-phone", "f-doc", "f-role", "f-gfirst", "f-glast"].forEach(id => $(id).value = "");
  $("f-minor").checked = false; $("guardian-box").hidden = true;
  ["c-image", "c-rodo", "c-marketing"].forEach(id => { $(id).checked = false; $(id).disabled = true; });
  clearSignature();
  resetCamera();
  gotoStep(1);
  show("view-wizard");
}
function gotoStep(n) {
  for (let i = 1; i <= STEPS; i++) $("wstep-" + i).hidden = i !== n;
  $("wizard-steps").innerHTML = Array.from({ length: 5 }, (_, i) =>
    `<div class="step-dot ${i + 1 < n ? "complete" : i + 1 === n ? "active" : ""}"></div>`).join("");
  window.scrollTo(0, 0);
  S.wizard && (S.wizard.step = n);
}
document.querySelectorAll("[data-next]").forEach(b => b.addEventListener("click", () => {
  const n = +b.dataset.next;
  if (validateStep(n - 1)) {
    if (n === 2) prepareConsentStep();
    if (n === 3) prepareSignStep();
    if (n === 4) prepareCameraStep();
    if (n === 5) renderSummary();
    gotoStep(n);
  }
}));
document.querySelectorAll("[data-prev]").forEach(b => b.addEventListener("click", () => gotoStep(+b.dataset.prev)));
$("btn-wizard-cancel").addEventListener("click", () => { stopCameraStream(); S.wizard = null; enterHome(); });
$("f-minor").addEventListener("change", e => { $("guardian-box").hidden = !e.target.checked; });

function collectPerson() {
  return {
    first: $("f-first").value.trim(), last: $("f-last").value.trim(),
    email: $("f-email").value.trim(), phone: $("f-phone").value.trim(),
    doc: $("f-doc").value.trim(), role: $("f-role").value.trim(),
    isMinor: $("f-minor").checked,
    gfirst: $("f-gfirst").value.trim(), glast: $("f-glast").value.trim(),
  };
}
function validateStep(n) {
  const err = $("err-" + n); if (err) err.hidden = true;
  if (n === 1) {
    const p = collectPerson();
    if (!p.first || !p.last) { err.textContent = "Imię i nazwisko są wymagane."; err.hidden = false; return false; }
    if (p.isMinor && (!p.gfirst || !p.glast)) { err.textContent = "Podaj dane opiekuna prawnego."; err.hidden = false; return false; }
    S.wizard.person = p;
    auditEvent(S.wizard, "dane", `wprowadzono dane: ${p.first} ${p.last}${p.isMinor ? " (małoletni, opiekun: " + p.gfirst + " " + p.glast + ")" : ""}`);
    return true;
  }
  if (n === 2) {
    if (!$("c-image").checked || !$("c-rodo").checked) { err.textContent = "Obie wymagane zgody (art. 81 i RODO) muszą być zaznaczone — po przeczytaniu treści do końca."; err.hidden = false; return false; }
    const proj = activeProject();
    for (const f of proj.files) {
      if (!S.wizard.attachChecks[f.id]) { err.textContent = `Wymagane potwierdzenie zapoznania się z dokumentem: ${f.name}.`; err.hidden = false; return false; }
    }
    S.wizard.consents = { image81: true, rodo: true, marketing: $("c-marketing").checked };
    S.wizard.attachments = proj.files.map(f => ({ fileId: f.id, name: f.name, hash: f.hash }));
    return true;
  }
  if (n === 3) {
    if (!sigDirty) { err.textContent = "Złóż podpis w ramce."; err.hidden = false; return false; }
    S.wizard.signature = exportSignature();
    auditEvent(S.wizard, "podpis", "złożono podpis odręczny (obraz, bez biometrii)");
    return true;
  }
  if (n === 4) {
    stopCameraStream();
    if (S.wizard.photoRequired && !S.wizard.photo) {
      err.textContent = "W tym projekcie zdjęcie jest obowiązkowe — wykonaj zdjęcie, aby kontynuować (albo administrator może wyłączyć ten wymóg w ustawieniach projektu).";
      err.hidden = false; return false;
    }
    auditEvent(S.wizard, "zdjęcie", S.wizard.photo ? "wykonano zdjęcie podpisującego (dowód)" : "pominięto (tryb zalecany)");
    return true;
  }
  return true;
}

/* --- krok 2: treść + dokumenty + scroll-to-enable --- */
function prepareConsentStep() {
  const proj = activeProject();
  const box = $("consent-text");
  S.wizard.templateText = consentText(S.vault, proj, S.wizard.person);
  box.textContent = S.wizard.templateText;
  box.scrollTop = 0;
  auditEvent(S.wizard, "treść", `wyświetlono treść zgody (szablon ${TEMPLATE_VERSION}${proj.customText ? ", treść własna projektu" : ""})`);
  const ab = $("attach-box");
  ab.innerHTML = "";
  S.wizard.attachChecks = {};
  for (const f of proj.files) {
    const row = document.createElement("div");
    row.className = "attach-row";
    row.innerHTML = `
      <div class="attach-info">📎 <b>${esc(f.name)}</b> <span class="tiny muted">(${(f.size / 1024).toFixed(0)} KB · SHA-256: ${f.hash.slice(0, 12)}…)</span></div>
      <button class="btn" type="button">👁 Otwórz</button>
      <label class="check"><input type="checkbox" disabled><span>Zapoznałem/am się z treścią tego dokumentu i akceptuję go</span></label>`;
    row.querySelector("button").addEventListener("click", () => {
      openFile(f);
      auditEvent(S.wizard, "dokument", `otwarto załączony dokument: ${f.name}`);
    });
    const cb = row.querySelector("input");
    cb.addEventListener("change", () => {
      S.wizard.attachChecks[f.id] = cb.checked;
      auditEvent(S.wizard, "dokument", `${f.name}: ${cb.checked ? "potwierdzono zapoznanie" : "wycofano potwierdzenie"}`);
    });
    ab.appendChild(row);
  }
  const enable = () => {
    if (box.scrollTop + box.clientHeight >= box.scrollHeight - 24) {
      ["c-image", "c-rodo", "c-marketing"].forEach(id => $(id).disabled = false);
      ab.querySelectorAll("input").forEach(i => i.disabled = false);
      auditEvent(S.wizard, "treść", "przewinięto treść do końca — odblokowano zgody");
      box.removeEventListener("scroll", enable);
    }
  };
  box.addEventListener("scroll", enable);
  if (box.scrollHeight <= box.clientHeight + 24) enable();
  ["c-image", "c-rodo", "c-marketing"].forEach(id => {
    $(id).onchange = (e) => auditEvent(S.wizard, "checkbox", `${id}: ${e.target.checked ? "zaznaczono" : "odznaczono"}`);
  });
}

/* --- krok 3: podpis --- */
const sig = $("sig-canvas"), sctx = sig.getContext("2d");
let sigDirty = false, drawing = false, lastPt = null;
function clearSignature() {
  sctx.fillStyle = "#ffffff"; sctx.fillRect(0, 0, sig.width, sig.height);
  sigDirty = false;
}
function canvasPoint(e) {
  const r = sig.getBoundingClientRect();
  return { x: (e.clientX - r.left) * (sig.width / r.width), y: (e.clientY - r.top) * (sig.height / r.height) };
}
sig.addEventListener("pointerdown", e => { drawing = true; lastPt = canvasPoint(e); sig.setPointerCapture(e.pointerId); });
sig.addEventListener("pointermove", e => {
  if (!drawing) return;
  const p = canvasPoint(e);
  sctx.strokeStyle = "#102040"; sctx.lineWidth = 3; sctx.lineCap = "round"; sctx.lineJoin = "round";
  sctx.beginPath(); sctx.moveTo(lastPt.x, lastPt.y); sctx.lineTo(p.x, p.y); sctx.stroke();
  lastPt = p; sigDirty = true;
});
["pointerup", "pointercancel"].forEach(ev => sig.addEventListener(ev, () => { drawing = false; }));
$("btn-sig-clear").addEventListener("click", () => { clearSignature(); auditEvent(S.wizard, "podpis", "wyczyszczono pole podpisu"); });
function exportSignature() { return sig.toDataURL("image/png"); }
function prepareSignStep() {
  const p = S.wizard.person;
  const signer = p.isMinor ? `${p.gfirst} ${p.glast} (opiekun prawny)` : `${p.first} ${p.last}`;
  $("sign-title").textContent = "3. Podpis — " + signer;
  $("sig-label").textContent = signer;
}

/* --- krok 4: zdjęcie --- */
let camStream = null;
function prepareCameraStep() {
  const req = !!activeProject().requirePhoto;
  S.wizard.photoRequired = req;
  $("cam-title").innerHTML = "4. Zdjęcie osoby podpisującej" +
    (req ? ' <span class="req-pill req">wymagane</span>' : ' <span class="req-pill opt">zalecane</span>');
  if (!S.wizard._photoNoticeLogged) {
    auditEvent(S.wizard, "zdjęcie", "pokazano informację o celu i podstawie zdjęcia-dowodu (art. 6 ust. 1 lit. f RODO)" + (req ? " — tryb obowiązkowy" : " — tryb zalecany"));
    S.wizard._photoNoticeLogged = true;
  }
}
function resetCamera() {
  stopCameraStream();
  $("cam-video").hidden = true; $("cam-photo").hidden = true;
  $("cam-placeholder").hidden = false;
  $("btn-cam-start").hidden = false; $("btn-cam-shot").hidden = true; $("btn-cam-retake").hidden = true;
  if (S.wizard) S.wizard.photo = null;
}
function stopCameraStream() {
  if (camStream) { camStream.getTracks().forEach(t => t.stop()); camStream = null; }
}
function detectOS() {
  const ua = navigator.userAgent || "";
  if (/iPhone|iPad|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)) return "ios";
  if (/Android/i.test(ua)) return "android";
  return "other";
}
async function startCamera() {
  $("err-4").hidden = true;
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { showCameraHelp("Unsupported"); return; }
  try {
    camStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user", width: { ideal: 1280 } }, audio: false });
    const v = $("cam-video");
    v.srcObject = camStream; v.hidden = false;
    $("cam-placeholder").hidden = true; $("cam-photo").hidden = true;
    $("btn-cam-start").hidden = true; $("btn-cam-shot").hidden = false; $("btn-cam-retake").hidden = true;
  } catch (e) {
    showCameraHelp(e && e.name ? e.name : "Error");
  }
}
$("btn-cam-start").addEventListener("click", startCamera);
function showCameraHelp(errName) {
  document.getElementById("cam-help") && document.getElementById("cam-help").remove();
  const os = detectOS();
  const noCam = errName === "NotFoundError" || errName === "DevicesNotFoundError" || errName === "OverconstrainedError";
  const unsupported = errName === "Unsupported" || errName === "NotSupportedError";
  let title, steps;
  if (unsupported) {
    title = "Aparat niedostępny w tym oknie";
    steps = `<li>Otwórz aplikację z <b>ikony na ekranie głównym</b> telefonu (nie z linku w wiadomości czy mailu).</li><li>Sprawdź, czy adres zaczyna się od <b>https://</b>.</li><li>Dotknij <b>Spróbuj ponownie</b>.</li>`;
  } else if (noCam) {
    title = "Nie znaleziono aparatu";
    steps = `<li>Aparat może być zajęty przez inną aplikację — zamknij np. Aparat, Zoom, Instagram.</li><li>Dotknij <b>Spróbuj ponownie</b>.</li><li>Jeśli to urządzenie nie ma aparatu, a zdjęcie nie jest wymagane — możesz je pominąć.</li>`;
  } else if (os === "ios") {
    title = "Pozwól na aparat (iPhone / iPad)";
    steps = `<li>Wyjdź na ekran główny i otwórz <b>Ustawienia</b> (szara ikona z kółkami zębatymi).</li>
      <li>Przewiń w dół do pozycji <b>SignOff</b> i dotknij jej.</li>
      <li>Dotknij <b>Aparat</b> — przełącznik ma zrobić się <b>zielony</b>.</li>
      <li>Wróć do SignOff i dotknij <b>Spróbuj ponownie</b>.</li>
      <li class="muted">Jeśli używasz w Safari bez instalacji: Ustawienia → Safari → Aparat → Zezwól.</li>`;
  } else if (os === "android") {
    title = "Pozwól na aparat (Android)";
    steps = `<li><b>Przytrzymaj palcem</b> ikonę SignOff na ekranie → dotknij <b>ⓘ Informacje o aplikacji</b>.</li>
      <li>Dotknij <b>Uprawnienia</b>, a potem <b>Aparat</b>.</li>
      <li>Wybierz <b>Zezwalaj</b>.</li>
      <li>Wróć do SignOff i dotknij <b>Spróbuj ponownie</b>.</li>
      <li class="muted">Możesz też dotknąć ikony <b>🔒 kłódki</b> obok adresu → Uprawnienia → Aparat → Zezwól.</li>`;
  } else {
    title = "Pozwól na aparat";
    steps = `<li>Kliknij ikonę <b>kłódki</b> lub <b>aparatu</b> w pasku adresu przeglądarki.</li>
      <li>Ustaw dostęp do <b>aparatu</b> na <b>Zezwól</b>.</li>
      <li>Kliknij <b>Spróbuj ponownie</b>.</li>`;
  }
  const ov = document.createElement("div");
  ov.id = "cam-help"; ov.className = "cam-help";
  ov.innerHTML = `<div class="cam-help-card">
    <div class="cam-help-icon">📷</div>
    <h3>${title}</h3>
    <p class="muted tiny">Ze względów bezpieczeństwa telefon nie pozwala aplikacji samej włączyć aparatu — trzeba zezwolić raz, ręcznie. Potem telefon zapamięta zgodę.</p>
    <ol class="cam-steps">${steps}</ol>
    <div class="cam-help-actions">
      <button class="btn primary big" id="cam-retry">Spróbuj ponownie</button>
      <button class="btn big" id="cam-close">Zamknij</button>
    </div>
  </div>`;
  document.body.appendChild(ov);
  $("cam-close").addEventListener("click", () => ov.remove());
  $("cam-retry").addEventListener("click", () => { ov.remove(); startCamera(); });
}
$("btn-cam-shot").addEventListener("click", () => {
  const v = $("cam-video"), c = $("cam-canvas");
  c.width = v.videoWidth; c.height = v.videoHeight;
  c.getContext("2d").drawImage(v, 0, 0);
  S.wizard.photo = c.toDataURL("image/jpeg", 0.82);
  stopCameraStream();
  v.hidden = true;
  const img = $("cam-photo"); img.src = S.wizard.photo; img.hidden = false;
  $("btn-cam-shot").hidden = true; $("btn-cam-retake").hidden = false;
});
$("btn-cam-retake").addEventListener("click", () => { resetCamera(); startCamera(); });

/* --- krok 5: podsumowanie --- */
function renderSummary() {
  const w = S.wizard, p = w.person;
  $("summary").innerHTML = `<table>
    <tr><td>Projekt</td><td><b>${esc(w.projectName)}</b> · zbiera: ${esc(S.user.name)}</td></tr>
    <tr><td>Osoba</td><td><b>${esc(p.first)} ${esc(p.last)}</b>${p.isMinor ? " (małoletni)" : ""}</td></tr>
    ${p.isMinor ? `<tr><td>Opiekun prawny</td><td>${esc(p.gfirst)} ${esc(p.glast)}</td></tr>` : ""}
    <tr><td>Kontakt</td><td>${esc(p.email) || "—"} ${p.phone ? "· " + esc(p.phone) : ""}</td></tr>
    <tr><td>Rola / scena</td><td>${esc(p.role) || "—"}</td></tr>
    <tr><td>Zezwolenie art. 81 (wizerunek)</td><td>✅ udzielone</td></tr>
    <tr><td>Zgoda RODO</td><td>✅ udzielona</td></tr>
    <tr><td>Zgoda marketingowa</td><td>${w.consents.marketing ? "✅ udzielona" : "— nieudzielona"}</td></tr>
    ${(w.attachments || []).length ? `<tr><td>Zaakceptowane dokumenty</td><td>${w.attachments.map(a => "📎 " + esc(a.name)).join("<br>")}</td></tr>` : ""}
    <tr><td>Podpis</td><td><img class="thumb" src="${w.signature}" alt="podpis"></td></tr>
    <tr><td>Zdjęcie</td><td>${w.photo ? `<img class="thumb" src="${w.photo}" alt="zdjęcie">` : "— pominięto"}</td></tr>
    <tr><td>Lokalizacja</td><td>${w.geo ? `${w.geo.lat}, ${w.geo.lon} (±${w.geo.acc} m)` : "niedostępna"}</td></tr>
    <tr><td>Zdarzeń w audit trail</td><td>${w.audit.length}</td></tr>
  </table>`;
}

/* --- zapis --- */
$("btn-save").addEventListener("click", async () => {
  const err = $("err-5"); err.hidden = true;
  const w = S.wizard;
  try {
    auditEvent(w, "zapis", "zatwierdzono i zapisano dokument");
    const record = {
      id: w.id, createdAt: new Date().toISOString(), startedAt: w.startedAt,
      projectId: w.projectId, projectName: w.projectName, producer: S.vault.producer,
      operator: S.user.name, operatorRole: S.user.role, operatorId: S.user.id,
      templateVersion: TEMPLATE_VERSION, templateText: w.templateText,
      person: w.person, consents: w.consents, attachments: w.attachments || [],
      signature: w.signature, photo: w.photo,
      audit: w.audit, device: w.device, geo: w.geo,
      status: "active", revocations: [],
    };
    record.templateTextHash = await sha256hex(w.templateText);
    record.hash = await sha256hex(JSON.stringify({ ...record, hash: undefined }));
    const prev = S.config.chainHead || "GENESIS";
    const chain = await sha256hex(prev + record.hash);
    const pack = await encryptJSON(S.key, record);
    const seq = (await getAll("records")).length + 1;
    await tx("records", "readwrite", s => s.put({ id: record.id, seq, pack, recordHash: record.hash, chain }));
    S.config.chainHead = chain;
    await saveConfig();
    record._chain = chain;
    S.records.push(record);
    scheduleSync();
    // Kopia e-mailem — nigdy nie blokuje zapisu zgody. Trzy przypadki: brak / błędny / poprawny adres.
    const base = `ID: ${record.id} · SHA-256: ${record.hash.slice(0, 16)}…`;
    const emailRaw = (w.person.email || "").trim();
    if (!emailRaw) {
      $("done-info").textContent = base + " · Brak e-maila — kopię przekaż ręcznie przyciskiem „Wyślij / udostępnij”.";
    } else if (!isValidEmail(emailRaw)) {
      $("done-info").textContent = base + ` · ⚠ Adres „${emailRaw}” wygląda na niepoprawny — kopii e-mail NIE wysłano. Przekaż PDF ręcznie.`;
      await tx("outbox", "readwrite", s => s.put({ id: record.id, to: emailRaw, name: `${w.person.first} ${w.person.last}`, queuedAt: new Date().toISOString(), status: "błędny adres — nie wysłano" }));
    } else {
      await tx("outbox", "readwrite", s => s.put({ id: record.id, to: emailRaw, name: `${w.person.first} ${w.person.last}`, queuedAt: new Date().toISOString(), status: "oczekuje" }));
      $("done-info").textContent = base + ` · Kopia dla ${emailRaw} w kolejce.`;
      if (syncCfg().autoEmail) {
        serverEmail(record).then(ok => {
          $("done-info").textContent = base + (ok
            ? ` · ✉ Kopia wysłana e-mailem na ${emailRaw}.`
            : ` · Kopia dla ${emailRaw} w kolejce — wyślemy automatycznie, gdy serwer będzie dostępny.`);
        }).catch(() => {});
      }
    }
    $("btn-done-pdf").onclick = () => downloadPDF(record);
    gotoStep(6);
  } catch (e) {
    err.textContent = "Błąd zapisu: " + e.message; err.hidden = false;
  }
});
$("btn-done-next").addEventListener("click", startWizard);
$("btn-done-home").addEventListener("click", enterHome);

/* ===================== Wysyłka kopii ===================== */
/* automatyczna wysyłka e-mail przez serwer (SMTP po stronie serwera) */
async function serverEmail(r) {
  const c = syncCfg();
  if (!c.url || !c.key || !isValidEmail(r.person.email) || !navigator.onLine) return false;
  try {
    const bytes = await buildPDF(r);
    const resp = await fetch(c.url.replace(/\/+$/, "") + "/api/email", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Sync-Key": c.key },
      body: JSON.stringify({
        to: r.person.email,
        subject: `Kopia podpisanej zgody — ${r.projectName}`,
        text: `Dzień dobry,\n\nw załączeniu kopia zgody podpisanej w dniu ${new Date(r.createdAt).toLocaleString("pl-PL")}.\nID dokumentu: ${r.id}\nSHA-256: ${r.hash}\n\nPozdrawiamy,\n${r.producer}`,
        filename: `zgoda-${r.person.last}-${r.person.first}.pdf`.toLowerCase().replace(/\s+/g, "-"),
        pdfBase64: b64.enc(bytes),
      }),
    });
    if (!resp.ok) return false;
    await markSent(r.id, "wysłano e-mailem (serwer)");
    return true;
  } catch { return false; }
}
async function sharePDF(r) {
  if (await serverEmail(r)) { alert("Kopia wysłana e-mailem przez serwer do: " + r.person.email); return; }
  const bytes = await buildPDF(r);
  const fname = `zgoda-${r.person.last}-${r.person.first}-${r.createdAt.slice(0, 10)}.pdf`.toLowerCase().replace(/\s+/g, "-");
  const file = new File([bytes], fname, { type: "application/pdf" });
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try {
      await navigator.share({ files: [file], title: "Kopia podpisanej zgody", text: `Kopia zgody podpisanej ${new Date(r.createdAt).toLocaleDateString("pl-PL")} — ${r.producer}.` });
      await markSent(r.id, "udostępniono (system)");
      return;
    } catch (e) { if (e.name === "AbortError") return; }
  }
  downloadPDF(r);
  if (r.person.email) {
    const subject = encodeURIComponent(`Kopia podpisanej zgody — ${r.projectName}`);
    const body = encodeURIComponent(
`Dzień dobry,

w załączeniu kopia zgody podpisanej w dniu ${new Date(r.createdAt).toLocaleString("pl-PL")}.
ID dokumentu: ${r.id}
SHA-256: ${r.hash}

Pozdrawiamy,
${r.producer}`);
    window.open(`mailto:${r.person.email}?subject=${subject}&body=${body}`, "_self");
    await markSent(r.id, "otwarto e-mail (załącz pobrany PDF)");
  }
}
async function markSent(id, status) {
  const row = await storeGet("outbox", id);
  if (!row) return;
  row.status = status; row.sentAt = new Date().toISOString();
  await tx("outbox", "readwrite", s => s.put(row));
}
/* Niezawodność: po powrocie sieci / przy wejściu na ekran główny ponawiamy nieudane wysyłki. */
let flushing = false;
async function flushOutbox() {
  const c = syncCfg();
  if (flushing || !c.url || !c.key || !c.autoEmail || !navigator.onLine || !S.key) return;
  flushing = true;
  try {
    for (const o of await getAll("outbox")) {
      if (o.sentAt || (o.status || "").startsWith("wysłano") || (o.status || "").startsWith("błędny")) continue;
      const r = S.records.find(x => x.id === o.id);
      if (r && isValidEmail(r.person.email)) await serverEmail(r);
    }
  } finally { flushing = false; }
}
$("btn-done-share").addEventListener("click", () => {
  const r = S.records[S.records.length - 1];
  if (r) sharePDF(r);
});

/* ===================== Szczegóły / cofnięcie ===================== */
function showDetail(id) {
  const r = S.records.find(x => x.id === id);
  if (!r) return;
  $("detail-title").textContent = `${r.person.first} ${r.person.last}`;
  const auditRows = r.audit.map(a => `<tr><td>${new Date(a.ts).toLocaleString("pl-PL")}</td><td>${esc(a.type)}</td><td>${esc(a.detail)}</td></tr>`).join("");
  const attach = (r.attachments || []).map(a => `<li>📎 ${esc(a.name)} <span class="tiny muted">(SHA-256: ${a.hash.slice(0, 16)}…)</span></li>`).join("");
  $("detail-body").innerHTML = `
    <div class="detail-card">
      <h3>Dokument</h3>
      <p>Data: <b>${new Date(r.createdAt).toLocaleString("pl-PL")}</b> · Projekt: ${esc(r.projectName || "—")}${r.operator ? " · Zebrał(a): " + esc(r.operator) : ""}<br>
      Status RODO: ${r.status === "active" ? '<span class="badge ok">aktywna</span>' : '<span class="badge revoked">cofnięta ' + new Date(r.revocations[0]?.ts).toLocaleDateString("pl-PL") + "</span>"} ·
      Zezwolenie art. 81: <span class="badge ok">udzielone</span> ·
      Marketing: ${r.consents.marketing ? '<span class="badge ok">tak</span>' : '<span class="badge planned">nie</span>'}</p>
      ${attach ? `<p><b>Zaakceptowane dokumenty:</b></p><ul>${attach}</ul>` : ""}
      <p>Podpis:<br><img class="sig" src="${r.signature}" alt="podpis"></p>
      ${r.photo ? `<p>Zdjęcie podpisującego:<br><img class="photo" src="${r.photo}" alt="zdjęcie"></p>` : ""}
    </div>
    <div class="detail-card">
      <h3>Dowód integralności</h3>
      <p class="tiny muted">SHA-256 dokumentu:</p><div class="hashbox">${r.hash}</div>
      <p class="tiny muted">Pozycja w łańcuchu integralności:</p><div class="hashbox">${r._chain}</div>
    </div>
    <div class="detail-card">
      <h3>Karta dowodowa (audit trail)</h3>
      <table class="audit-table"><tr><th>Czas</th><th>Zdarzenie</th><th>Szczegóły</th></tr>${auditRows}</table>
      <p class="tiny muted">Urządzenie: ${esc(r.device.ua)}<br>Strefa: ${esc(r.device.tz)} · Ekran: ${esc(r.device.screen)}${r.geo ? `<br>Lokalizacja: ${r.geo.lat}, ${r.geo.lon} (±${r.geo.acc} m)` : ""}</p>
    </div>
    <div class="detail-actions">
      <button class="btn primary" id="btn-detail-pdf">⬇ Pobierz PDF</button>
      <button class="btn" id="btn-detail-share">📤 Wyślij / udostępnij</button>
      ${r.status === "active" && isAdmin() ? '<button class="btn danger" id="btn-revoke">⛔ Odnotuj cofnięcie zgody RODO</button>' : ""}
    </div>`;
  $("btn-detail-pdf").addEventListener("click", () => downloadPDF(r));
  $("btn-detail-share").addEventListener("click", () => sharePDF(r));
  const rv = $("btn-revoke");
  if (rv) rv.addEventListener("click", () => revokeRodo(r));
  show("view-detail");
}
$("btn-detail-back").addEventListener("click", enterHome);

async function revokeRodo(r) {
  if (!confirm(`Odnotować cofnięcie zgody RODO przez ${r.person.first} ${r.person.last}?\n\nCofnięcie działa na przyszłość — nie unieważnia zezwolenia art. 81 dla już wyprodukowanego materiału. Dokument pozostaje w archiwum jako dowód.`)) return;
  r.status = "revoked-rodo";
  r.revocations.push({ ts: new Date().toISOString(), type: "rodo", note: "cofnięcie odnotowane przez: " + S.user.name });
  r.audit.push({ ts: new Date().toISOString(), type: "cofnięcie", detail: "odnotowano cofnięcie zgody RODO (skutek na przyszłość)" });
  const row = await storeGet("records", r.id);
  row.pack = await encryptJSON(S.key, r);
  row.revoked = true;
  await tx("records", "readwrite", s => s.put(row));
  scheduleSync();
  showDetail(r.id);
}

/* ===================== Ustawienia ===================== */
function enterSettings() {
  applyRole();
  if (isAdmin()) {
    $("set-producer").value = S.vault.producer;
    $("set-email").value = S.vault.email || "";
    const c = syncCfg();
    $("sync-url").value = c.url || "";
    $("sync-key").value = c.key || "";
    $("sync-auto").checked = c.auto !== false;
    $("sync-autoemail").checked = !!c.autoEmail;
    $("sync-status").textContent = S.config.lastSync ? "Ostatnia synchronizacja: " + new Date(S.config.lastSync).toLocaleString("pl-PL") : "Jeszcze nie synchronizowano.";
    $("restore-list").innerHTML = "";
    renderProjects(); renderAccounts(); renderOutbox(); renderStorageInfo();
  }
  show("view-settings");
}
$("btn-settings-back").addEventListener("click", enterHome);
$("btn-set-save").addEventListener("click", async () => {
  S.vault.producer = $("set-producer").value.trim() || S.vault.producer;
  S.vault.email = $("set-email").value.trim();
  await saveVault();
  enterHome();
});

/* --- projekty --- */
function renderProjects() {
  const box = $("projects-list");
  box.innerHTML = "";
  const employees = S.config.accounts.filter(a => a.active);
  for (const p of S.vault.projects) {
    p.allowedUserIds = p.allowedUserIds || [];
    const count = S.records.filter(r => !r.corrupted && r.projectId === p.id).length;
    const card = document.createElement("div");
    card.className = "proj-card";
    card.innerHTML = `
      <div class="proj-head"><b>📁 ${esc(p.name)}</b><span class="tiny muted">${count} zgód</span></div>
      <label class="tiny">Własna treść zgody (puste = standardowa klauzula wizerunkowa; RODO dołączane zawsze)
        <textarea rows="3" placeholder="np. treść regulaminu wydarzenia…">${esc(p.customText || "")}</textarea>
      </label>
      <div class="proj-allowed"><span class="tiny muted">Uprawnieni (nikt zaznaczony = wszyscy):</span></div>
      <label class="check tiny-check photo-req"><input type="checkbox" ${p.requirePhoto ? "checked" : ""}><span>📷 Zdjęcie-dowód <b>obowiązkowe</b> w tym projekcie</span></label>
      <div class="proj-rec">💡 Rekomendacja: dla bohaterów pierwszoplanowych i wywiadów włącz zdjęcie obowiązkowe — istotnie wzmacnia dowód udzielenia zgody. Dla scen z tłem / przechodniami wystarczy tryb zalecany (domyślny).</div>
      <div class="proj-files"></div>
      <div class="wnav-mini">
        <button class="btn" data-act="savetext">💾 Zapisz</button>
        <button class="btn" data-act="addfile">📎 Dodaj plik PDF do podpisu</button>
        ${S.vault.projects.length > 1 ? '<button class="btn danger" data-act="del">🗑 Usuń projekt</button>' : ""}
      </div>
      <input type="file" accept="application/pdf" hidden>`;
    // zdjęcie obowiązkowe
    card.querySelector(".photo-req input").addEventListener("change", async (e) => {
      p.requirePhoto = e.target.checked;
      await saveVault();
    });
    // uprawnienia
    const allowedBox = card.querySelector(".proj-allowed");
    for (const acc of employees) {
      const lbl = document.createElement("label");
      lbl.className = "check tiny-check";
      lbl.innerHTML = `<input type="checkbox" ${p.allowedUserIds.includes(acc.id) ? "checked" : ""}><span>${esc(acc.name)} <span class="tiny muted">(${roleLabel(acc.role)})</span></span>`;
      lbl.querySelector("input").addEventListener("change", async (e) => {
        if (e.target.checked) { if (!p.allowedUserIds.includes(acc.id)) p.allowedUserIds.push(acc.id); }
        else p.allowedUserIds = p.allowedUserIds.filter(x => x !== acc.id);
        await saveVault();
      });
      allowedBox.appendChild(lbl);
    }
    // pliki
    const filesBox = card.querySelector(".proj-files");
    const renderFiles = () => {
      filesBox.innerHTML = p.files.length
        ? p.files.map((f, i) => `<div class="attach-row"><div class="attach-info">📎 <b>${esc(f.name)}</b> <span class="tiny muted">(${(f.size / 1024).toFixed(0)} KB)</span></div><button class="btn" data-open="${i}">👁</button><button class="btn danger" data-rm="${i}">✕</button></div>`).join("")
        : '<p class="tiny muted">Brak załączonych dokumentów.</p>';
      filesBox.querySelectorAll("[data-open]").forEach(b => b.addEventListener("click", () => openFile(p.files[+b.dataset.open])));
      filesBox.querySelectorAll("[data-rm]").forEach(b => b.addEventListener("click", async () => {
        const f = p.files[+b.dataset.rm];
        if (!confirm(`Usunąć plik „${f.name}” z projektu? Już podpisane zgody zachowują jego nazwę i hash.`)) return;
        p.files.splice(+b.dataset.rm, 1);
        await saveVault(); renderFiles();
      }));
    };
    renderFiles();
    const fileInput = card.querySelector("input[type=file]");
    card.querySelector("[data-act=addfile]").addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", async (e) => {
      const f = e.target.files[0]; e.target.value = "";
      if (!f) return;
      try { await addFileToProject(p, f); renderFiles(); }
      catch (ex) { alert(ex.message); }
    });
    card.querySelector("[data-act=savetext]").addEventListener("click", async () => {
      p.customText = card.querySelector("textarea").value;
      await saveVault();
      alert("Zapisano.");
    });
    const del = card.querySelector("[data-act=del]");
    if (del) del.addEventListener("click", async () => {
      if (!confirm(`Usunąć projekt „${p.name}”? Zebrane zgody pozostaną w archiwum.`)) return;
      S.vault.projects = S.vault.projects.filter(x => x.id !== p.id);
      if (S.vault.activeProjectId === p.id) S.vault.activeProjectId = S.vault.projects[0].id;
      await saveVault(); renderProjects();
    });
    box.appendChild(card);
  }
}
$("btn-add-project").addEventListener("click", async () => {
  const name = $("new-project-name").value.trim();
  if (!name) { alert("Podaj nazwę projektu."); return; }
  S.vault.projects.push({ id: uuid(), name, customText: "", files: [], allowedUserIds: [], requirePhoto: false });
  $("new-project-name").value = "";
  await saveVault(); renderProjects();
});

/* --- konta użytkowników (tylko admin) --- */
async function wrapDEKForPin(pin) {
  const salt = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
  const kek = await deriveKEK(pin, salt);
  return { salt, wrap: await encryptBytes(kek, S.dekRaw) };
}
function renderAccounts() {
  const box = $("accounts-list");
  box.innerHTML = "";
  for (const acc of S.config.accounts) {
    const row = document.createElement("div");
    row.className = "attach-row";
    row.innerHTML = `
      <div class="attach-info"><b>${esc(acc.name)}</b>
        <span class="tiny muted">${roleLabel(acc.role)}${acc.active ? "" : " · DEZAKTYWOWANE"}${acc.id === S.user.id ? " · (to Ty)" : ""}</span></div>
      <button class="btn" data-act="reset">🔑 Reset PIN</button>
      ${acc.id !== S.user.id ? `<button class="btn" data-act="toggle">${acc.active ? "⏸ Dezaktywuj" : "▶ Aktywuj"}</button><button class="btn danger" data-act="del">🗑</button>` : ""}
      <div class="reset-box" hidden>
        <input type="password" placeholder="nowy PIN (6+ cyfr)" inputmode="numeric" class="reset-pin">
        <button class="btn primary" data-act="confirm">Zatwierdź</button>
      </div>`;
    row.querySelector("[data-act=reset]").addEventListener("click", () => {
      const rb = row.querySelector(".reset-box"); rb.hidden = !rb.hidden;
    });
    row.querySelector("[data-act=confirm]").addEventListener("click", async () => {
      const pin = row.querySelector(".reset-pin").value;
      if (!PIN_RE.test(pin)) { alert("PIN: min. 6 cyfr."); return; }
      const { salt, wrap } = await wrapDEKForPin(pin);
      acc.salt = salt; acc.wrap = wrap; acc.fails = 0; acc.lockUntil = 0;
      await saveConfig(); scheduleSync();
      alert(`Nowy PIN dla „${acc.name}” ustawiony.`);
      renderAccounts();
    });
    const tg = row.querySelector("[data-act=toggle]");
    if (tg) tg.addEventListener("click", async () => {
      if (acc.role === "admin" && acc.active && S.config.accounts.filter(a => a.active && a.role === "admin").length <= 1) { alert("Musi pozostać co najmniej jeden aktywny administrator."); return; }
      acc.active = !acc.active;
      await saveConfig(); scheduleSync(); renderAccounts();
    });
    const dl = row.querySelector("[data-act=del]");
    if (dl) dl.addEventListener("click", async () => {
      if (acc.role === "admin" && S.config.accounts.filter(a => a.active && a.role === "admin").length <= 1) { alert("Musi pozostać co najmniej jeden aktywny administrator."); return; }
      if (!confirm(`Usunąć konto „${acc.name}”? Zebrane przez nie zgody pozostają w archiwum.`)) return;
      S.config.accounts = S.config.accounts.filter(a => a.id !== acc.id);
      await saveConfig(); scheduleSync(); renderAccounts();
    });
    box.appendChild(row);
  }
}
$("btn-add-acc").addEventListener("click", async () => {
  const err = $("acc-error"); err.hidden = true;
  const name = $("new-acc-name").value.trim();
  const role = $("new-acc-role").value;
  const pin = $("new-acc-pin").value, pin2 = $("new-acc-pin2").value;
  const fail = (m) => { err.textContent = m; err.hidden = false; };
  if (!name) return fail("Podaj imię i nazwisko.");
  if (!PIN_RE.test(pin)) return fail("PIN: min. 6 cyfr.");
  if (pin !== pin2) return fail("PIN-y nie są zgodne.");
  const { salt, wrap } = await wrapDEKForPin(pin);
  S.config.accounts.push({ id: uuid(), name, role, salt, wrap, fails: 0, lockUntil: 0, active: true, createdAt: new Date().toISOString() });
  await saveConfig(); scheduleSync();
  $("new-acc-name").value = ""; $("new-acc-pin").value = ""; $("new-acc-pin2").value = "";
  renderAccounts();
});

/* --- zmiana własnego PIN (każdy użytkownik) --- */
$("btn-change-pin").addEventListener("click", async () => {
  const err = $("pin-error"); err.hidden = true;
  const np = $("pin-new").value, np2 = $("pin-new2").value;
  if (!PIN_RE.test(np)) { err.textContent = "Nowy PIN musi mieć co najmniej 6 cyfr."; err.hidden = false; return; }
  if (np !== np2) { err.textContent = "Nowe kody PIN nie są zgodne."; err.hidden = false; return; }
  const { salt, wrap } = await wrapDEKForPin(np);
  S.user.salt = salt; S.user.wrap = wrap; S.user.fails = 0; S.user.lockUntil = 0;
  await saveConfig(); scheduleSync();
  $("pin-new").value = $("pin-new2").value = "";
  alert("Twój PIN został zmieniony.");
});

/* --- kolejka + pamięć --- */
async function renderOutbox() {
  const rows = await getAll("outbox");
  const box = $("outbox-list");
  if (!rows.length) { box.innerHTML = '<div class="empty tiny">Kolejka pusta.</div>'; return; }
  box.innerHTML = "";
  for (const o of rows) {
    const div = document.createElement("div");
    div.className = "record";
    div.innerHTML = `<div class="who"><b>${esc(o.name)}</b><span>${esc(o.to)} · ${new Date(o.queuedAt).toLocaleString("pl-PL")}</span></div><span class="badge planned">${esc(o.status)}</span><button class="btn">✉ Wyślij</button>`;
    div.querySelector("button").addEventListener("click", async () => {
      const r = S.records.find(x => x.id === o.id);
      if (r) { await sharePDF(r); renderOutbox(); }
    });
    box.appendChild(div);
  }
}
async function renderStorageInfo() {
  const el = $("storage-info");
  try {
    const persisted = navigator.storage && navigator.storage.persisted ? await navigator.storage.persisted() : false;
    const est = navigator.storage && navigator.storage.estimate ? await navigator.storage.estimate() : null;
    el.textContent = `Pamięć trwała: ${persisted ? "✓ przyznana" : "✗ nieprzyznana — zainstaluj aplikację (Dodaj do ekranu głównego)"}` +
      (est ? ` · zajęte ${(est.usage / 1048576).toFixed(1)} MB z ${(est.quota / 1048576).toFixed(0)} MB` : "");
  } catch { el.textContent = ""; }
}

/* ===================== Generowanie PDF ===================== */
let fontCache = null;
async function loadFonts(doc) {
  if (!fontCache) {
    const [reg, bold] = await Promise.all([
      fetch("vendor/DejaVuSans.ttf").then(r => r.arrayBuffer()),
      fetch("vendor/DejaVuSans-Bold.ttf").then(r => r.arrayBuffer()),
    ]);
    fontCache = { reg, bold };
  }
  doc.registerFontkit(window.fontkit);
  return { font: await doc.embedFont(fontCache.reg, { subset: true }), fontB: await doc.embedFont(fontCache.bold, { subset: true }) };
}
function wrapText(text, font, size, maxW) {
  const out = [];
  for (const para of text.split("\n")) {
    if (!para.trim()) { out.push(""); continue; }
    let line = "";
    for (const word of para.split(" ")) {
      const probe = line ? line + " " + word : word;
      if (font.widthOfTextAtSize(probe, size) > maxW && line) { out.push(line); line = word; }
      else line = probe;
    }
    if (line) out.push(line);
  }
  return out;
}
async function buildPDF(r) {
  const { PDFDocument, rgb } = window.PDFLib;
  const doc = await PDFDocument.create();
  const { font, fontB } = await loadFonts(doc);
  const A4 = [595.28, 841.89], M = 50, W = A4[0] - 2 * M;
  const navy = rgb(0.06, 0.11, 0.18), gray = rgb(0.35, 0.42, 0.52);
  let page = doc.addPage(A4), y = A4[1] - M;
  const ensure = (need) => { if (y - need < M) { page = doc.addPage(A4); y = A4[1] - M; } };
  const text = (s, { size = 9.5, bold = false, color = navy, gap = 3 } = {}) => {
    const f = bold ? fontB : font;
    for (const ln of wrapText(s, f, size, W)) {
      ensure(size + gap);
      if (ln) page.drawText(ln, { x: M, y, size, font: f, color });
      y -= size + gap;
    }
  };

  page.drawRectangle({ x: 0, y: A4[1] - 36, width: A4[0], height: 36, color: navy });
  page.drawText("ZGODA / DOKUMENT PODPISANY ELEKTRONICZNIE — SignOff by Offhand", { x: M, y: A4[1] - 24, size: 10, font: fontB, color: rgb(1, 1, 1) });
  y = A4[1] - 60;
  text(`Projekt: „${r.projectName}”  ·  Administrator: ${r.producer}`, { size: 11, bold: true });
  text(`Data i czas: ${new Date(r.createdAt).toLocaleString("pl-PL")}  ·  ID dokumentu: ${r.id}${r.operator ? "  ·  Zebrał(a): " + r.operator : ""}`, { size: 9, color: gray, gap: 10 });

  const p = r.person;
  text("OSOBA UDZIELAJĄCA ZGODY", { bold: true, size: 10.5, gap: 5 });
  text(`${p.first} ${p.last}${p.isMinor ? "  (osoba małoletnia)" : ""}`, { size: 11 });
  if (p.isMinor) text(`Opiekun prawny: ${p.gfirst} ${p.glast}`, { size: 10 });
  text(`E-mail: ${p.email || "—"}   Telefon: ${p.phone || "—"}   Nr dokumentu: ${p.doc || "—"}   Rola: ${p.role || "—"}`, { size: 9, color: gray, gap: 10 });

  text("TREŚĆ OŚWIADCZENIA", { bold: true, size: 10.5, gap: 5 });
  text(r.templateText, { size: 8.5, gap: 2.5 });
  y -= 8;

  text("WYRAŻONE ZGODY", { bold: true, size: 10.5, gap: 5 });
  text("[X] Zezwolenie na rozpowszechnianie wizerunku (art. 81 pr. aut.) — UDZIELONE", { size: 9.5 });
  text("[X] Zgoda na przetwarzanie danych osobowych (art. 6 ust. 1 lit. a RODO) — UDZIELONA", { size: 9.5 });
  text(`[${r.consents.marketing ? "X" : "  "}] Zgoda dodatkowa (marketing/promocja) — ${r.consents.marketing ? "UDZIELONA" : "NIEUDZIELONA"}`, { size: 9.5, gap: 6 });
  if ((r.attachments || []).length) {
    text("ZAAKCEPTOWANE DOKUMENTY ZAŁĄCZONE (pełna treść na końcu pliku):", { bold: true, size: 9.5, gap: 4 });
    for (const a of r.attachments) text(`[X] ${a.name}  ·  SHA-256: ${a.hash}`, { size: 7.5, gap: 2.5 });
    y -= 6;
  }

  ensure(150);
  text("PODPIS" + (p.isMinor ? " OPIEKUNA PRAWNEGO" : ""), { bold: true, size: 10.5, gap: 5 });
  const sigImg = await doc.embedPng(r.signature);
  const sw = 200, sh = sw * (sigImg.height / sigImg.width);
  ensure(sh + 20);
  page.drawImage(sigImg, { x: M, y: y - sh, width: sw, height: sh });
  page.drawLine({ start: { x: M, y: y - sh - 4 }, end: { x: M + sw, y: y - sh - 4 }, color: gray, thickness: 0.7 });
  if (r.photo) {
    const ph = await doc.embedJpg(r.photo);
    const pw2 = 120, ph2 = pw2 * (ph.height / ph.width);
    page.drawImage(ph, { x: M + sw + 40, y: y - ph2 + 10, width: pw2, height: ph2 });
    page.drawText("zdjęcie wykonane przy podpisie", { x: M + sw + 40, y: y - ph2 + 2, size: 6.5, font, color: gray });
  }
  y -= sh + 18;
  text(p.isMinor ? `${p.gfirst} ${p.glast} — rodzic / opiekun prawny` : `${p.first} ${p.last}`, { size: 9, color: gray });

  /* Karta dowodowa */
  page = doc.addPage(A4); y = A4[1] - M;
  page.drawRectangle({ x: 0, y: A4[1] - 36, width: A4[0], height: 36, color: navy });
  page.drawText("KARTA DOWODOWA (AUDIT TRAIL)", { x: M, y: A4[1] - 24, size: 10, font: fontB, color: rgb(1, 1, 1) });
  y = A4[1] - 60;
  text(`Dokument ID: ${r.id}  ·  Szablon: ${r.templateVersion}  ·  Zebrał(a): ${r.operator || "—"} (${r.operatorRole === "admin" ? "administrator" : "pracownik"})`, { size: 9, color: gray, gap: 8 });
  text("INTEGRALNOŚĆ", { bold: true, size: 10.5, gap: 5 });
  text(`SHA-256 dokumentu: ${r.hash}`, { size: 8 });
  text(`SHA-256 treści szablonu: ${r.templateTextHash}`, { size: 8 });
  text(`Pozycja w łańcuchu integralności (hash-chain): ${r._chain || "—"}`, { size: 8, gap: 8 });
  text("URZĄDZENIE I KONTEKST", { bold: true, size: 10.5, gap: 5 });
  text(`Przeglądarka/urządzenie: ${r.device.ua}`, { size: 8 });
  text(`Ekran: ${r.device.screen}  ·  Język: ${r.device.lang}  ·  Strefa czasowa: ${r.device.tz}`, { size: 8 });
  text(`Geolokalizacja: ${r.geo ? `${r.geo.lat}, ${r.geo.lon} (dokładność ±${r.geo.acc} m)` : "niedostępna"}`, { size: 8, gap: 8 });
  text("PRZEBIEG CZYNNOŚCI", { bold: true, size: 10.5, gap: 5 });
  for (const a of r.audit) text(`${a.ts}   ${a.type.toUpperCase()}   ${a.detail}`, { size: 7.5, gap: 2 });
  y -= 10;
  if (r.revocations.length) {
    text("COFNIĘCIA", { bold: true, size: 10.5, gap: 5 });
    for (const v of r.revocations) text(`${v.ts} — cofnięcie zgody ${v.type.toUpperCase()} (${v.note})`, { size: 8, color: rgb(0.7, 0.2, 0.15) });
    y -= 6;
  }
  text("Podpis złożono w formie dokumentowej (art. 77² KC). Zapisano wyłącznie obraz podpisu — bez danych biometrycznych. " +
       "Dokument przeznaczony do opatrzenia kwalifikowanym znacznikiem czasu i pieczęcią elektroniczną (eIDAS) po synchronizacji z usługą zaufania.", { size: 7.5, color: gray });

  /* Załączniki — scalenie pełnej treści */
  for (const a of (r.attachments || [])) {
    try {
      const row = await storeGet("files", a.fileId);
      if (!row) continue;
      const buf = await decryptBytes(S.key, row.pack);
      const src = await PDFDocument.load(buf);
      const pages = await doc.copyPages(src, src.getPageIndices());
      for (const pg of pages) doc.addPage(pg);
    } catch { /* załącznik nieodczytywalny — hash pozostaje w dokumencie */ }
  }
  return doc.save();
}
async function downloadPDF(r) {
  const bytes = await buildPDF(r);
  const blob = new Blob([bytes], { type: "application/pdf" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `zgoda-${r.person.last}-${r.person.first}-${r.createdAt.slice(0, 10)}.pdf`.toLowerCase().replace(/\s+/g, "-");
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

boot();
