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

/* Kod odzyskiwania (awaryjny reset PIN-u bez nikogo). Opakowuje ten sam DEK co PIN —
   alfabet bez znaków mylących (I, O, 0, 1). Format: XXXXX-XXXXX-XXXXX-XXXXX (20 znaków). */
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function genRecoveryCode() {
  const r = crypto.getRandomValues(new Uint8Array(20));
  let s = ""; for (let i = 0; i < r.length; i++) s += RECOVERY_ALPHABET[r[i] % RECOVERY_ALPHABET.length];
  return s.match(/.{1,5}/g).join("-");
}
const normalizeRecovery = (code) => (code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
async function wrapDEKWith(secretStr, dek) {
  const salt = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
  const kek = await deriveKEK(secretStr, salt);
  return { salt, wrap: await encryptBytes(kek, dek || S.dekRaw) };
}

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
const views = ["view-lock", "view-home", "view-wizard", "view-detail", "view-settings"];
function show(view) { views.forEach(v => $(v).hidden = v !== view); window.scrollTo(0, 0); renderUpdateBanner(); }
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const isAdmin = () => S.user && (S.user.role === "admin" || S.user.role === "support");
const roleLabel = (r) => r === "admin" ? "Administrator" : r === "support" ? "Support" : r === "inne" ? "Inne" : "Pracownik";
function activeProject() { return allowedProjects().find(p => p.id === S.vault.activeProjectId) || allowedProjects()[0]; }
function allowedProjects() {
  if (isAdmin()) return S.vault.projects;
  return S.vault.projects.filter(p => !(p.allowedUserIds || []).length || p.allowedUserIds.includes(S.user.id));
}
async function saveVault() { await metaSet("vault", await encryptJSON(S.key, S.vault)); scheduleSync(); }
async function saveConfig() { await metaSet("config", S.config); }

/* ===================== Modale UI (zamiast natywnych alert/confirm/prompt) ===================== */
function uiModal({ title = "", message = "", okLabel = "OK", cancelLabel = null, danger = false, input = null }) {
  return new Promise((resolve) => {
    const hasInput = input !== null;
    const overlay = document.createElement("div");
    overlay.className = "ui-modal";
    overlay.innerHTML =
      `<div class="ui-modal-card" role="dialog" aria-modal="true">` +
      (title ? `<h3 class="ui-modal-title">${esc(title)}</h3>` : "") +
      (message ? `<p class="ui-modal-msg">${esc(message).replace(/\n/g, "<br>")}</p>` : "") +
      (hasInput ? `<input class="ui-modal-input" type="${input.type || "text"}" inputmode="${input.inputmode || ""}" placeholder="${esc(input.placeholder || "")}" value="${esc(input.value || "")}">` : "") +
      `<div class="ui-modal-actions">` +
      (cancelLabel ? `<button class="btn ui-modal-cancel">${esc(cancelLabel)}</button>` : "") +
      `<button class="btn primary ${danger ? "danger" : ""} ui-modal-ok">${esc(okLabel)}</button>` +
      `</div></div>`;
    document.body.appendChild(overlay);
    const inputEl = overlay.querySelector(".ui-modal-input");
    const done = (val) => { document.removeEventListener("keydown", onKey); overlay.remove(); resolve(val); };
    const ok = () => done(hasInput ? (inputEl ? inputEl.value : "") : true);
    const cancel = () => done(hasInput ? null : false);
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); cancelLabel ? cancel() : ok(); }
      else if (e.key === "Enter" && (hasInput || !cancelLabel)) { e.preventDefault(); ok(); }
    };
    overlay.querySelector(".ui-modal-ok").addEventListener("click", ok);
    const cb = overlay.querySelector(".ui-modal-cancel");
    if (cb) cb.addEventListener("click", cancel);
    overlay.addEventListener("mousedown", (e) => { if (e.target === overlay) cancelLabel ? cancel() : ok(); });
    document.addEventListener("keydown", onKey);
    if (inputEl) { inputEl.focus(); inputEl.select(); }
    else overlay.querySelector(".ui-modal-ok").focus();
  });
}
function uiAlert(message, opt = {}) { return uiModal({ title: opt.title || "", message, okLabel: opt.okLabel || "OK" }); }
function uiConfirm(message, opt = {}) { return uiModal({ title: opt.title || "Potwierdzenie", message, okLabel: opt.okLabel || "Tak", cancelLabel: opt.cancelLabel || "Anuluj", danger: !!opt.danger }); }
function uiPrompt(message, opt) {
  const o = typeof opt === "string" ? { value: opt } : (opt || {});
  return uiModal({ title: o.title || "", message, okLabel: o.okLabel || "OK", cancelLabel: o.cancelLabel || "Anuluj", input: { value: o.value || "", placeholder: o.placeholder || "", type: o.type || "text", inputmode: o.inputmode || "" } });
}
/* Pokazanie kodu odzyskiwania. Jeśli poszedł mailem (emailedTo) — komunikat „nie musisz pamiętać".
   Jeśli nie udało się wysłać — prosimy o ręczne zapisanie (jedyny moment, gdy go widać). */
function showRecoveryCode(code, who, emailedTo) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "ui-modal";
    const msg = emailedTo
      ? `✅ Wysłaliśmy ten kod na e-mail: <b>${esc(emailedTo)}</b>. <b>Nie musisz go pamiętać</b> — znajdziesz go w skrzynce, gdy zapomnisz PIN-u. (Możesz też skopiować poniżej.)`
      : `Maile nie są jeszcze włączone, więc <b>zapisz ten kod</b> (np. menedżer haseł). Po włączeniu maili kod możesz wysłać sobie przyciskiem „🆘 Kod odzyskiwania" w Ustawieniach → Konta.`;
    overlay.innerHTML =
      `<div class="ui-modal-card" role="dialog" aria-modal="true">` +
      `<h3 class="ui-modal-title">🆘 Kod odzyskiwania${who ? " — " + esc(who) : ""}</h3>` +
      `<p class="ui-modal-msg">${msg}<br><span class="tiny muted">Kto ma ten kod, może ustawić nowy PIN tego konta.</span></p>` +
      `<div class="reccode-box">${esc(code)}</div>` +
      `<div class="ui-modal-actions">` +
      `<button class="btn reccode-copy">📋 Kopiuj</button>` +
      `<button class="btn primary reccode-ok">${emailedTo ? "OK" : "Zapisałem/am"}</button>` +
      `</div></div>`;
    document.body.appendChild(overlay);
    const done = () => { overlay.remove(); resolve(true); };
    overlay.querySelector(".reccode-ok").addEventListener("click", done);
    overlay.querySelector(".reccode-copy").addEventListener("click", async (e) => {
      try { await navigator.clipboard.writeText(code); e.target.textContent = "✅ Skopiowano"; }
      catch { e.target.textContent = "Zaznacz kod i skopiuj ręcznie"; }
    });
  });
}

/* ===================== Administratorzy danych (podmioty na zgodzie) =====================
   Rejestr administratorów danych (RODO). Każda zgoda używa administratora przypisanego
   do projektu, a jeśli projekt go nie ma — administratora domyślnego. */
/* Realne dane administratora Offhand (potwierdzone: biała lista VAT MF + CEIDG, NIP 5423140283).
   Nazwa „offhand Hanna Nobis" z małym „offhand" — zgodnie z wpisem w CEIDG. */
const LEGACY_ADMIN_NAME = "Offhand Hanna Nobis";
const ADMIN_DEFAULTS = { name: "offhand Hanna Nobis", address: "ul. Szara 14/5, 00-420 Warszawa", taxId: "5423140283", email: "hankanobis@offhandfilms.com" };
function normalizeVault(v) {
  if (!v) return false;
  let changed = false;
  if (!Array.isArray(v.admins) || !v.admins.length) {
    const baseName = (v.producer && v.producer !== LEGACY_ADMIN_NAME) ? v.producer : ADMIN_DEFAULTS.name;
    v.admins = [{ id: uuid(), name: baseName, address: ADMIN_DEFAULTS.address, taxId: ADMIN_DEFAULTS.taxId, email: v.email || ADMIN_DEFAULTS.email }];
    changed = true;
  }
  if (!v.defaultAdminId || !v.admins.find(a => a.id === v.defaultAdminId)) { v.defaultAdminId = v.admins[0].id; changed = true; }
  const da = v.admins.find(a => a.id === v.defaultAdminId);
  if (da) {
    if (da.name === LEGACY_ADMIN_NAME) { da.name = ADMIN_DEFAULTS.name; changed = true; } // ujednolicenie do pisowni z CEIDG
    // uzupełnij puste pola domyślnego administratora realnymi danymi (tylko gdy to wciąż Offhand i pole puste — nie nadpisuje ręcznych zmian)
    if (da.name === ADMIN_DEFAULTS.name) {
      if (!da.address) { da.address = ADMIN_DEFAULTS.address; changed = true; }
      if (!da.taxId) { da.taxId = ADMIN_DEFAULTS.taxId; changed = true; }
      if (!da.email) { da.email = ADMIN_DEFAULTS.email; changed = true; }
    }
  }
  const dn = (v.admins.find(a => a.id === v.defaultAdminId) || v.admins[0]).name;
  if (v.producer !== dn) { v.producer = dn; changed = true; } // mirror dla zgodności wstecznej
  // Biblioteka zgód i dokumentów (wspólna, przypinana do projektów). Migracja starych project.files[] → pozycje „dokument".
  if (!Array.isArray(v.library)) { v.library = []; changed = true; }
  if (!Array.isArray(v.loginLog)) { v.loginLog = []; changed = true; }
  (v.projects || []).forEach(p => {
    if (Array.isArray(p.files) && p.files.length) {
      for (const f of p.files) {
        v.library.push({ id: f.id || uuid(), kind: "dokument", name: f.name || "Dokument", desc: "", type: "pdf",
          fileId: f.id, fileName: f.name, size: f.size, pages: f.pages, hash: f.hash,
          required: f.required !== false, projectIds: [p.id], createdAt: f.addedAt || new Date().toISOString() });
      }
      p.files = [];
      changed = true;
    }
  });
  return changed;
}
function defaultAdmin() { return (S.vault.admins || []).find(a => a.id === S.vault.defaultAdminId) || (S.vault.admins || [])[0]; }
/* Biblioteka: pozycje przypięte do projektu (opcjonalnie filtrowane po rodzaju). */
function projectLibrary(proj, kind) {
  if (!proj || !S.vault || !Array.isArray(S.vault.library)) return [];
  return S.vault.library.filter(i => (i.projectIds || []).includes(proj.id) && (!kind || i.kind === kind));
}
/* dokumenty (pliki PDF) przypięte do projektu — do wglądu/akceptacji w kroku zgody */
function projectDocs(proj) { return projectLibrary(proj).filter(i => i.type === "pdf"); }
/* adresy, na które wysyłamy kody odzyskiwania / prośby o reset (admin nie musi nic pamiętać) */
function adminEmails() {
  const set = new Set();
  ((S.vault && S.vault.admins) || []).forEach(a => { if (a.email && isValidEmail(a.email)) set.add(a.email.trim()); });
  if (S.config && S.config.adminEmail && isValidEmail(S.config.adminEmail)) set.add(S.config.adminEmail.trim());
  return [...set];
}
function projectAdmin(proj) {
  const byId = proj && proj.adminId && (S.vault.admins || []).find(a => a.id === proj.adminId);
  return byId || defaultAdmin();
}
function adminLine(a) {
  if (!a) return "";
  let s = a.name || "";
  if (a.address) s += ", " + a.address;
  if (a.taxId) s += " (NIP/ID: " + a.taxId + ")";
  return s;
}

/* ===================== Szablon zgody ===================== */
const TEMPLATE_VERSION = "4.9-PL";
function defaultClause(cfg, proj, p) {
  const who = p.isMinor
    ? `Ja, ${p.gfirst} ${p.glast}, działając jako rodzic/opiekun prawny małoletniego(-iej) ${p.first} ${p.last},`
    : `Ja, ${p.first} ${p.last},`;
  const subj = p.isMinor
    ? "wizerunku, głosu, wypowiedzi i podobizny małoletniego(-iej), a także jego/jej artystycznych wykonań (o ile występują)"
    : "mojego wizerunku, głosu, wypowiedzi i podobizny, a także moich artystycznych wykonań (o ile występują)";
  const paid = !!proj.paid;
  const grant = paid ? "" : "nieodpłatnego, ";
  return (
`ZEZWOLENIE NA ROZPOWSZECHNIANIE WIZERUNKU I WYPOWIEDZI (art. 81 pr. aut.) ORAZ PRZENIESIENIE PRAW

${who} niniejszym udzielam ${cfg.producer} (dalej „Producent”) ${grant}nieograniczonego czasowo ani terytorialnie zezwolenia na utrwalanie oraz rozpowszechnianie ${subj}, utrwalonych w nagraniach audiowizualnych oraz na zdjęciach (dalej łącznie „Nagrania”), w związku z realizacją filmu prowadzonego pod roboczym tytułem „${proj.name}” (dalej „Film”), niezależnie od jego ostatecznego tytułu. Zezwolenie dotyczy wszystkich Nagrań powstałych w ramach tego przedsięwzięcia, we wszystkich fazach produkcji i niezależnie od daty ich powstania (a nie tylko z dnia podpisania niniejszego oświadczenia).

Zezwolenie obejmuje korzystanie z Nagrań w ramach Filmu oraz utworów, do których Film zostanie włączony, w całości i we fragmentach, w celach realizacji, promocji, reklamy oraz eksploatacji Filmu, na wszelkich nośnikach i we wszelkich mediach — znanych obecnie oraz powstałych w przyszłości — w najszerszym dopuszczalnym prawem zakresie, w szczególności na następujących polach eksploatacji:
• utrwalanie i zwielokrotnianie Nagrań dowolną techniką i na dowolnym nośniku (m.in. techniką cyfrową, magnetyczną, światłoczułą, optyczną, drukarską oraz zapisu komputerowego), w nieograniczonej liczbie egzemplarzy, w tym na nośnikach wideo, DVD, CD, na taśmie światłoczułej i magnetycznej oraz na dysku komputerowym;
• wprowadzanie egzemplarzy do obrotu, ich użyczanie oraz najem;
• wprowadzanie Nagrań do pamięci komputera oraz do sieci teleinformatycznych i telekomunikacyjnych (w tym Internetu), a także do pamięci serwerów funkcjonujących w takich sieciach;
• publiczne wykonanie, wystawienie, wyświetlenie i odtworzenie (w tym w kinach, na festiwalach i pokazach, na pokładach samolotów i statków oraz w hotelach);
• nadawanie za pomocą wizji lub fonii, przewodowe i bezprzewodowe, przez stację naziemną;
• nadawanie za pośrednictwem satelity (przekaz satelitarny), w sposób kodowany i niekodowany;
• reemitowanie, tj. równoczesne i integralne rozpowszechnianie Nagrań przez podmiot inny niż pierwotnie nadający — w tym w sieciach telewizji kablowej, w sieciach telekomunikacyjnych i internetowych oraz na platformach cyfrowych, a także w ramach telewizji mobilnej (DVB-H, DVB-SH), w tym simulcasting i webcasting;
• rozpowszechnianie w ramach odpłatności za pokaz (pay-per-view), tj. za opłatą wnoszoną przez użytkownika końcowego za pojedynczy dostęp;
• rozpowszechnianie w ramach usługi wideo na żądanie (video-on-demand, near-video-on-demand, push-video-on-demand) we wszelkich formułach (w tym TVOD, AVOD, FVOD i SVOD) oraz w ramach abonamentu na żądanie (subscription-on-demand / SVOD);
• publiczne udostępnianie Nagrań w taki sposób, aby każdy mógł mieć do nich dostęp w wybranym przez siebie miejscu i czasie, w tym streaming, downloading i podcasting;
• wykorzystanie w celu promocji i reklamy Filmu, jego producentów, nadawców i dystrybutorów — w szczególności w zwiastunach, plakatach, publikacjach, mediach społecznościowych oraz w przekazach reklamowych każdego rodzaju; merchandising;
• eksploatacja dla celów kronikarskich, archiwalnych, dokumentacyjnych, edukacyjnych, reporterskich i przeglądowych, łącznie lub rozłącznie z innymi utworami;
• tłumaczenie, przystosowywanie i zmiana układu Nagrań oraz tworzenie i korzystanie z opracowań (utworów zależnych), w tym w innych wersjach językowych.

Producent jest uprawniony do montażu, kadrowania, skracania, uzupełniania, adaptacji, opracowywania oraz zestawiania Nagrań z innymi materiałami, według swojego uznania — w tym z wykorzystaniem narzędzi sztucznej inteligencji (AI), na przykład do obróbki obrazu i dźwięku, zmiany lub ukrycia głosu albo twarzy (anonimizacja), poprawy jakości oraz tworzenia materiałów pochodnych — z poszanowaniem moich dóbr osobistych i bez prawa do wykorzystania w sposób obraźliwy lub ogólnie uznany za nieetyczny. Zezwolenie udzielane jest na rzecz Producenta oraz jego następców prawnych, przy czym Producent ma prawo przenieść nabyte prawa oraz udzielać dalszych zgód, upoważnień i licencji na rzecz osób trzecich — w szczególności koproducentów, dystrybutorów, nadawców i platform — bez konieczności uzyskiwania mojej dodatkowej zgody.

Zrzekam się roszczeń (istniejących i przyszłych) wobec Producenta oraz jego następców prawnych z tytułu korzystania z Nagrań w sposób zgodny z niniejszym oświadczeniem; zrzeczenie to nie obejmuje roszczeń z tytułu naruszenia moich dóbr osobistych ani wykorzystania Nagrań w sposób sprzeczny z niniejszym oświadczeniem.

${paid
  ? `Zezwoleń i zgód objętych niniejszym oświadczeniem udzielam za wynagrodzeniem, którego wysokość i warunki reguluje odrębny dokument (umowa). Wynagrodzenie to wyczerpuje wszelkie moje roszczenia z tytułu udziału w Filmie oraz udzielonych praw i zgód. Z uwagi na odpłatny charakter niniejszego oświadczenia udzielone zezwolenia oraz przeniesienie praw są nieodwołalne w najszerszym dopuszczalnym prawem zakresie i nie mogą być przeze mnie jednostronnie wypowiedziane ani odwołane w okresie trwania ochrony tych praw; nie ogranicza to prawa do cofnięcia zgody na przetwarzanie danych osobowych (RODO) na zasadach opisanych w klauzuli poniżej.`
  : `Możliwość udziału w Filmie stanowi należyte i wyłączne wynagrodzenie z tytułu udzielonych zezwoleń i zgód; nie przysługuje mi z tego tytułu żadne inne wynagrodzenie, niezależnie od tego, czy Nagrania zostaną wykorzystane w Filmie.`}`);
}
function rodoClause(cfg) {
  return (
`KLAUZULA INFORMACYJNA I ZGODA — DANE OSOBOWE (RODO)

1. Administratorem danych osobowych (w tym wizerunku, głosu, imienia i nazwiska oraz podanych danych kontaktowych) jest ${cfg._admin ? adminLine(cfg._admin) : cfg.producer}.${cfg._admin && cfg._admin.email ? `\n   Kontakt w sprawie ochrony danych i realizacji praw: ${cfg._admin.email}.` : ""}
2. Wyrażam zgodę na przetwarzanie moich danych osobowych w celu realizacji, promocji i eksploatacji Filmu — na podstawie art. 6 ust. 1 lit. a RODO (zgoda) oraz art. 6 ust. 1 lit. f RODO (prawnie uzasadniony interes administratora); w zakresie wizerunku i wypowiedzi podstawą jest także zezwolenie z art. 81 pr. aut. powyżej.
3. Dane mogą być przekazywane oraz powierzane podmiotom współpracującym przy produkcji, promocji i dystrybucji Filmu — w szczególności koproducentom, nadawcom, dystrybutorom, platformom emisyjnym, ubezpieczycielom oraz usługodawcom Administratora — w tym, w niezbędnym zakresie, do państw spoza Europejskiego Obszaru Gospodarczego — z zastosowaniem zabezpieczeń przewidzianych w RODO (w szczególności standardowych klauzul umownych zatwierdzonych przez Komisję Europejską) i przy zapewnieniu poziomu ochrony nie niższego niż obowiązujący w Unii Europejskiej.
4. Administrator ma prawo przenieść prawa i obowiązki związane z przetwarzaniem na swoich następców prawnych. Dane nie będą wykorzystywane do marketingu bezpośredniego bez odrębnej zgody ani do zautomatyzowanego podejmowania decyzji (profilowania).
5. Dane będą przechowywane przez okres eksploatacji Filmu, a dokument zgody — dodatkowo przez okres przedawnienia roszczeń.
6. Przysługuje mi prawo dostępu do danych i uzyskania ich kopii, sprostowania, usunięcia, ograniczenia przetwarzania, przenoszenia danych, sprzeciwu oraz wniesienia skargi do Prezesa UODO.
7. Zgodę na przetwarzanie danych (oraz zgodę dodatkową) mogę cofnąć w każdej chwili, niezależnie od pozostałych, ze skutkiem na przyszłość. Cofnięcie nie wpływa na zgodność z prawem przetwarzania dokonanego przed cofnięciem ani na nabyte zgodnie z prawem zezwolenie na rozpowszechnianie wizerunku w już wyprodukowanym materiale (art. 81 pr. aut. stanowi odrębną podstawę). Cofnięcie zgody może rodzić roszczenia odszkodowawcze po stronie Producenta, jeżeli spowoduje szkodę na polu realizacji lub promocji Filmu.
8. Podanie danych jest dobrowolne, lecz niezbędne do udziału w Filmie.

INFORMACJA O PODPISIE ELEKTRONICZNYM

Dokument podpisywany jest podpisem elektronicznym w formie dokumentowej (art. 77² Kodeksu cywilnego). Zapisywany jest wyłącznie obraz podpisu — aplikacja nie rejestruje danych biometrycznych. Dokument otrzymuje znacznik czasu, sumę kontrolną SHA-256 oraz kartę dowodową (audit trail). Kopia dokumentu zostanie przekazana podpisującemu.`);
}
function summaryClause(cfg, proj, p) {
  const paid = !!proj.paid;
  const adminName = cfg._admin ? cfg._admin.name : cfg.producer;
  const whose = p.isMinor ? "wizerunku, głosu i wypowiedzi Twojego dziecka (podopiecznego)" : "Twojego wizerunku, głosu i wypowiedzi";
  return (
`W SKRÓCIE — najważniejsze w prostych słowach (pełne, wiążące warunki znajdują się poniżej)

• Zgadzasz się na wykorzystanie ${whose} w filmie o roboczym tytule „${proj.name}” (tytuł może się jeszcze zmienić) oraz w jego promocji.
• Bez ograniczeń: kino, telewizja, internet, festiwale — w kraju i za granicą, bez limitu czasu.
• Dotyczy wszystkich nagrań w ramach projektu, a nie tylko z dnia podpisu.
• Materiał można montować, skracać, tłumaczyć i obrabiać — także przy użyciu sztucznej inteligencji (AI), np. do zmiany lub ukrycia głosu albo twarzy — nigdy w sposób obraźliwy.
• Prawa nabywa ${adminName} i może je przekazać dalej (koproducenci, dystrybutorzy, platformy).
• ${paid ? "Za udział otrzymasz wynagrodzenie — jego wysokość reguluje odrębny dokument (umowa)." : "Nie otrzymujesz wynagrodzenia — sam udział w filmie jest „wynagrodzeniem”."}
• Twoje dane osobowe: przetwarzane do realizacji i promocji filmu. Masz prawo wglądu, poprawy i usunięcia, a zgodę na dane (RODO) możesz cofnąć w każdej chwili.`);
}
// Rozbite części zgody: streszczenie, sekcja wizerunkowa (+ przypięte zgody z biblioteki), sekcja RODO.
// Wyświetlane osobno w kreatorze; sklejone przez consentText() do rekordu/PDF/hasza.
function consentParts(cfg, proj, p) {
  const admin = projectAdmin(proj);
  const acfg = Object.assign({}, cfg, { producer: admin ? admin.name : cfg.producer, _admin: admin });
  const usingCustom = !!(proj.customText || "").trim();
  const summary = usingCustom ? "" : summaryClause(acfg, proj, p);
  let image = usingCustom ? proj.customText.trim() : defaultClause(acfg, proj, p);
  // dodatkowe zgody tekstowe przypięte do projektu (z biblioteki) — dołączane do sekcji wizerunkowej
  for (const it of projectLibrary(proj, "zgoda")) {
    if (it.type === "text" && (it.text || "").trim()) {
      image += "\n\n" + (it.name ? it.name.toUpperCase() + "\n\n" : "") + it.text.trim();
    }
  }
  return { summary, image, rodo: rodoClause(acfg) };
}
function consentText(cfg, proj, p) {
  const { summary, image, rodo } = consentParts(cfg, proj, p);
  const head = summary ? summary + "\n\n————————————————————\n\n" : "";
  return head + image + "\n\n" + rodo;
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
function geoErrText(e) {
  if (!e) return "nieznany błąd";
  if (e.code === 1) return "brak zgody na lokalizację (zezwól w przeglądarce)";
  if (e.code === 2) return "pozycja niedostępna (brak GPS/sieci)";
  if (e.code === 3) return "przekroczono czas oczekiwania";
  return e.message || "nieznany błąd";
}
async function geoPermissionState() {
  try { if (navigator.permissions && navigator.permissions.query) return (await navigator.permissions.query({ name: "geolocation" })).state; } catch {}
  return null;
}
/* Najlepsze namierzenie: „nasłuchuje" pozycji do maxMs i bierze NAJDOKŁADNIEJSZY odczyt
   (GPS poprawia się z każdą sekundą). Zwraca {lat,lon,acc} albo null. */
function getBestPosition(maxMs) {
  return new Promise(resolve => {
    if (!navigator.geolocation) return resolve(null);
    let best = null, id = null, done = false;
    const finish = () => { if (done) return; done = true; try { if (id != null) navigator.geolocation.clearWatch(id); } catch {} resolve(best); };
    try {
      id = navigator.geolocation.watchPosition(
        p => {
          const c = { lat: +p.coords.latitude.toFixed(5), lon: +p.coords.longitude.toFixed(5), acc: Math.round(p.coords.accuracy) };
          if (!best || c.acc < best.acc) best = c;
          if (best.acc <= 20) finish(); // już wystarczająco dokładnie
        },
        () => finish(),
        { enableHighAccuracy: true, timeout: maxMs, maximumAge: 0 });
    } catch { return resolve(null); }
    setTimeout(finish, maxMs);
  });
}
/* „Pokazano raz" trzymane w DWÓCH miejscach na urządzeniu (localStorage + IndexedDB),
   żeby przeżyło aktualizację apki i ewentualne czyszczenie jednego z magazynów.
   To jest PER-URZĄDZENIE (nie synchronizuje się) — każdy fizyczny sprzęt pyta raz. */
async function geoIsPrimed() {
  try { if (localStorage.getItem("geoPrimed") === "1") return true; } catch {}
  try { if (await metaGet("geoPrimed")) return true; } catch {}
  return false;
}
async function markGeoPrimed() {
  try { localStorage.setItem("geoPrimed", "1"); } catch {}
  try { await metaSet("geoPrimed", true); } catch {}
}
/* Komunikat „priming" PRZED systemowym pytaniem o lokalizację (raz na urządzenie). */
async function ensureGeoPrimed() {
  if (await geoIsPrimed()) return;
  const st = await geoPermissionState();
  // zgoda już udzielona lub odrzucona w przeglądarce → nie pytamy ponownie (przeżywa aktualizacje)
  if (st === "granted" || st === "denied") { await markGeoPrimed(); return; }
  await uiAlert(
    "Za chwilę telefon zapyta o dostęp do lokalizacji. Wybierz „Zezwól” (jeśli jest opcja — najlepiej „zawsze”/„podczas używania aplikacji”).\n\n" +
    "Miejsce podpisania to ważny dowód: bez lokalizacji materiał dowodowy jest słabszy, gdyby ktoś podważył zgodę.",
    { title: "📍 Lokalizacja = mocniejszy dowód" });
  await markGeoPrimed();
}
async function tryGeolocate(w) {
  if (!navigator.geolocation) { auditEvent(w, "geolokalizacja", "niedostępna: brak wsparcia w przeglądarce"); return; }
  const best = await getBestPosition(15000);
  if (best) {
    w.geo = best;
    auditEvent(w, "geolokalizacja", `${best.lat}, ${best.lon} (±${best.acc} m)`);
    if (w.step === 5 && typeof renderSummary === "function") renderSummary();
  } else {
    const st = await geoPermissionState();
    auditEvent(w, "geolokalizacja", "niedostępna: " + (st === "denied" ? "brak zgody na lokalizację (zezwól w ustawieniach przeglądarki)" : "pozycja niedostępna / przekroczono czas"));
  }
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
let pendingUpdateWorker = null;
function showUpdateBanner(worker) { pendingUpdateWorker = worker; renderUpdateBanner(); }
function renderUpdateBanner() {
  const existing = document.getElementById("update-banner");
  // Nie pokazuj paska w trakcie wypełniania zgody — zasłaniałby przycisk „Dalej”.
  const inWizard = $("view-wizard") && !$("view-wizard").hidden;
  if (!pendingUpdateWorker || inWizard) { if (existing) existing.remove(); return; }
  if (existing) return;
  const bar = document.createElement("div");
  bar.id = "update-banner";
  bar.innerHTML = `<span>✨ Dostępna nowa wersja aplikacji</span><button class="btn" id="btn-update">Odśwież</button>`;
  document.body.appendChild(bar);
  $("btn-update").addEventListener("click", () => {
    $("btn-update").textContent = "Aktualizuję…";
    try { pendingUpdateWorker.postMessage({ type: "SKIP_WAITING" }); } catch (e) {}
    // Siatka bezpieczeństwa: controllerchange bywa niewywoływany (m.in. iOS) — przeładuj ręcznie.
    setTimeout(() => location.reload(), 2000);
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
  enterLogin();
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

/* --- pierwsze uruchomienie: tylko PIN pierwszego administratora; resztę ustawia się w aplikacji --- */
$("btn-setup").addEventListener("click", async () => {
  const name = $("setup-name").value.trim() || "Administrator";
  const pin = $("setup-pin").value, pin2 = $("setup-pin2").value;
  const err = $("setup-error"); err.hidden = true;
  const fail = (m) => { err.textContent = m; err.hidden = false; };
  if (!PIN_RE.test(pin)) return fail("PIN musi mieć co najmniej 6 cyfr.");
  if (pin !== pin2) return fail("PIN-y nie są zgodne.");

  const dekRaw = crypto.getRandomValues(new Uint8Array(32)).buffer;
  const salt = b64.enc(crypto.getRandomValues(new Uint8Array(16)));
  const kek = await deriveKEK(pin, salt);
  const recCode = genRecoveryCode();
  const rec = await wrapDEKWith(normalizeRecovery(recCode), dekRaw);
  const acc = { id: uuid(), name, role: "admin", salt, wrap: await encryptBytes(kek, dekRaw), recSalt: rec.salt, recWrap: rec.wrap, fails: 0, lockUntil: 0, active: true, createdAt: new Date().toISOString() };
  S.config = { v: 3, deviceId: uuid(), deviceName: "SignOff · " + (navigator.platform || "urządzenie"), accounts: [acc], adminEmail: ADMIN_DEFAULTS.email, chainHead: "GENESIS", lastSync: null };
  await saveConfig();
  S.dekRaw = dekRaw;
  S.key = await importDEK(dekRaw);
  S.user = acc;
  S.vault = { producer: "offhand Hanna Nobis", email: "", projects: [], activeProjectId: null, sync: { url: "", key: "", auto: true, autoEmail: true } };
  normalizeVault(S.vault);
  await saveVault();
  const emailedTo = await emailRecoveryCode(recCode, name);
  await showRecoveryCode(recCode, name, emailedTo);
  enterHome();
});

/* --- pierwsze uruchomienie: „Mam już konto — przywróć z chmury" (pobiera konta + dane z backupu) --- */
$("btn-firstrun-restore").addEventListener("click", () => {
  const b = $("firstrun-restore-box"); b.hidden = !b.hidden;
  if (!b.hidden) setTimeout(() => $("fr-pass").focus(), 60);
});
$("btn-fr-go").addEventListener("click", async () => {
  const st = $("fr-status"), pass = $("fr-pass").value.trim();
  if (!pass) { st.textContent = "🛑 Wpisz hasło konta technicznego (dostaniesz je od Marka)."; return; }
  if (!navigator.onLine) { st.textContent = "🛑 Brak internetu — przywracanie wymaga połączenia."; return; }
  st.textContent = "Łączę z chmurą i pobieram kopię…";
  try {
    S.vault = { fb: { enabled: true, apiKey: FB_DEFAULTS.apiKey, projectId: FB_DEFAULTS.projectId, email: FB_DEFAULTS.email, password: pass } };
    const devices = await fbListDevices();
    if (!devices.length) { S.vault = null; st.textContent = "🛑 W chmurze nie ma jeszcze żadnej kopii do przywrócenia."; return; }
    devices.sort((a, b) => (b.updatedAt || "").localeCompare(a.updatedAt || ""));
    const data = await fbDownload(devices[0].deviceId);
    await applyBackup(data.payload);
    // własny identyfikator urządzenia (osobny slot kopii w chmurze)
    const cfg = await metaGet("config");
    if (cfg) { cfg.deviceId = uuid(); cfg.deviceName = "SignOff · " + (navigator.platform || "urządzenie"); await metaSet("config", cfg); }
    st.textContent = "✅ Przywrócono konta i dane. Za chwilę zaloguj się swoim PIN-em.";
    setTimeout(() => location.reload(), 900);
  } catch (e) {
    S.vault = null;
    st.textContent = "🛑 " + (/INVALID|PASSWORD|EMAIL|CREDENTIAL/i.test(e.message || "") ? "Błędne hasło konta technicznego." : (e.message || "Nie udało się przywrócić."));
  }
});

/* --- logowanie kontem --- */
let accSelected = null;
function enterLogin() {
  $("lock-error").hidden = true;
  if ($("setup-error")) $("setup-error").hidden = true;
  // pierwsze uruchomienie — brak konta: ten sam ekran, tryb „ustaw PIN"
  if (!S.config) {
    $("lock-title").textContent = "Witaj";
    $("firstrun").hidden = false;
    $("loginbox").hidden = true;
    show("view-lock");
    return;
  }
  $("firstrun").hidden = true;
  $("loginbox").hidden = false;
  accSelected = null;
  $("lock-pin").value = ""; if (typeof renderPinDots === "function") renderPinDots();
  $("lock-title").textContent = "Zaloguj się";
  const actives = S.config.accounts.filter(a => a.active);
  const area = $("account-area");
  if (actives.length === 1) {
    // jeden użytkownik — wyświetlony, wystarczy PIN
    accSelected = actives[0];
    area.innerHTML = `<div class="single-account">Zalogujesz się jako <b>${esc(actives[0].name)}</b> <span class="op-role">${roleLabel(actives[0].role)}</span></div>`;
    $("login-hint").textContent = "Podaj PIN, aby się zalogować.";
    setTimeout(() => $("lock-pin").focus(), 60);
  } else {
    // wielu użytkowników — lista wybieralna
    $("login-hint").textContent = "Wybierz konto i podaj PIN.";
    const opts = actives.map(a => `<option value="${a.id}">${esc(a.name)} · ${roleLabel(a.role)}</option>`).join("");
    area.innerHTML = `<select id="account-select"><option value="" disabled selected>— wybierz konto —</option>${opts}</select>`;
    $("account-select").addEventListener("change", (e) => {
      accSelected = actives.find(a => a.id === e.target.value) || null;
      $("lock-pin").focus();
    });
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
    if (normalizeVault(S.vault)) await saveVault();
    // adres, na który ekran logowania wysyła prośby o reset PIN-u (dostępny zanim ktoś się zaloguje)
    const da = defaultAdmin();
    if (da && da.email && S.config.adminEmail !== da.email) { S.config.adminEmail = da.email; await saveConfig(); }
    await recordLogin(acc, "logowanie");
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
/* Rejestr logowań (kto / kiedy / gdzie) — w zaszyfrowanej skrzynce, widoczny dla admina i supportu. */
async function recordLogin(acc, kind) {
  if (!S.vault) return;
  if (!Array.isArray(S.vault.loginLog)) S.vault.loginLog = [];
  // ostatnia znana lokalizacja na tym urządzeniu — gdy świeżej nie uda się pobrać, wpis nie będzie pusty
  let lastGeo = null;
  for (let i = S.vault.loginLog.length - 1; i >= 0; i--) {
    const g = S.vault.loginLog[i].geo;
    if (g && g.lat != null) { lastGeo = { lat: g.lat, lon: g.lon, acc: g.acc, approx: true }; break; }
  }
  const entry = {
    at: new Date().toISOString(), userId: acc.id, name: acc.name, role: acc.role,
    kind: kind || "logowanie",
    device: (S.config && S.config.deviceName) || (navigator.platform || "urządzenie"),
    geo: lastGeo,
  };
  S.vault.loginLog.push(entry);
  if (S.vault.loginLog.length > 300) S.vault.loginLog = S.vault.loginLog.slice(-300);
  await saveVault();
  resolveLoginLocation(entry); // GPS → IP → ostatnia znana (nie blokuje logowania)
}
/* Skuteczne ustalenie miejsca: 1) GPS, 2) przybliżone z adresu IP (miasto/kraj), 3) ostatnia znana. */
async function resolveLoginLocation(entry) {
  // 1. GPS — TYLKO gdy zgoda już udzielona. Przy logowaniu NIE pytamy (pytanie pada przy 1. zgodzie).
  const st = await geoPermissionState();
  if (st === "granted") {
    const gps = await getBestPosition(10000);
    if (gps) entry.geo = { ...gps, source: "gps" };
  } else if (st === "denied") {
    entry.geoBlocked = true;
  }
  // 2. Przybliżone z IP (miasto/kraj) — bez żadnego pytania (gdy nie ma dokładnego GPS)
  if (!(entry.geo && entry.geo.source === "gps") && navigator.onLine) {
    try {
      const r = await fetch("https://ipapi.co/json/");
      if (r.ok) {
        const d = await r.json();
        if (d && d.latitude != null && d.longitude != null) {
          entry.geo = { lat: +(+d.latitude).toFixed(4), lon: +(+d.longitude).toFixed(4), city: [d.city, d.country_name].filter(Boolean).join(", "), approx: true, source: "ip" };
        }
      }
    } catch { /* brak sieci / API niedostępne — zostaje „ostatnia znana" */ }
  }
  // 3. (gdy nic nie wyszło, zostaje „ostatnia znana" ustawiona przy tworzeniu)
  await saveVault();
  // wspólny rejestr w chmurze (zaszyfrowany E2E) — gdy kopia w chmurze włączona
  try { if (fbCfg() && navigator.onLine) await fbPushLogin(entry); } catch {}
}
function nameInitials(name) {
  const parts = (name || "").trim().split(/\s+/).filter(Boolean);
  return parts.length ? parts.map(w => w[0].toUpperCase()).join(".") + "." : "—";
}
function loginEntryHtml(e) {
  let detail;
  if (!e.geo) detail = e.geoBlocked ? "lokalizacja zablokowana w przeglądarce" : "brak lokalizacji";
  else {
    const coords = `${e.geo.lat}, ${e.geo.lon}`;
    // współrzędne jako tekst (zawsze do odczytania/skopiowania) + oficjalny link do map (bez przekierowań)
    const map = `<a href="https://www.google.com/maps/search/?api=1&query=${e.geo.lat}%2C${e.geo.lon}" target="_blank" rel="noopener noreferrer">🗺 mapa</a>`;
    let suffix;
    if (e.geo.source === "ip") suffix = `${e.geo.city ? " · " + esc(e.geo.city) : ""} (wg IP, przybliżona)`;
    else if (e.geo.approx) suffix = " (ostatnia znana)";
    else suffix = ` (±${e.geo.acc} m)`;
    detail = `<span class="loc-coords">${coords}</span> ${map}${suffix}`;
  }
  return `<div class="attach-row"><div class="attach-info">
    <b>${esc(nameInitials(e.name))}</b>${e.kind && e.kind !== "logowanie" ? ` <span class="tiny muted">${esc(e.kind)}</span>` : ""}
    <span class="loc-wrap"><button class="loc-pin" type="button" title="Pokaż lokalizację">📍</button><span class="loc-detail tiny muted" hidden>${detail}</span></span><br>
    <span class="tiny muted">🕘 ${new Date(e.at).toLocaleString("pl-PL")} · 📱 ${esc(e.device || "")}</span></div></div>`;
}
function renderLoginLogList(box, log) {
  const arr = (log || []).slice().sort((a, b) => (b.at || "").localeCompare(a.at || "")); // najnowsze na górze
  box.innerHTML = arr.length ? arr.map(loginEntryHtml).join("") : '<p class="tiny muted">Brak wpisów.</p>';
  box.querySelectorAll(".loc-pin").forEach(b => b.addEventListener("click", () => { const d = b.nextElementSibling; if (d) d.hidden = !d.hidden; }));
}
function renderLoginLog() {
  const box = $("loginlog-list"); if (!box) return;
  renderLoginLogList(box, (S.vault && S.vault.loginLog) || []); // najpierw to urządzenie (szybko)
  // dołącz wpisy z chmury (wszystkie urządzenia), jeśli kopia w chmurze włączona
  if (fbCfg() && navigator.onLine) {
    fbListLogins().then(cloud => {
      if (!cloud.length) return;
      const local = (S.vault && S.vault.loginLog) || [];
      const seen = new Set(), merged = [];
      [...cloud, ...local].forEach(e => { const k = (e.at || "") + "|" + (e.device || ""); if (!seen.has(k)) { seen.add(k); merged.push(e); } });
      renderLoginLogList(box, merged);
    }).catch(() => {});
  }
}
{
  const c = $("btn-loginlog-clear");
  if (c) c.addEventListener("click", async () => {
    if (!await uiConfirm("Wyczyścić wszystkie logi? Tej operacji nie można cofnąć.", { danger: true })) return;
    S.vault.loginLog = []; await saveVault(); renderLoginLog();
  });
  // „Logs" otwiera się dopiero po potrójnym kliknięciu (zwykły klik nie rozwija)
  const sum = document.querySelector("#grp-loginlog > summary");
  if (sum) {
    let n = 0, t = null;
    sum.addEventListener("click", (e) => {
      e.preventDefault();
      n++; clearTimeout(t); t = setTimeout(() => { n = 0; }, 700);
      if (n >= 3) { n = 0; const d = document.getElementById("grp-loginlog"); d.open = !d.open; if (d.open) renderLoginLog(); }
    });
  }
}
$("btn-unlock").addEventListener("click", login);
$("lock-pin").addEventListener("keydown", e => { if (e.key === "Enter") login(); });
/* PIN jako kropki (wizualnie wg wzorca) — pole pozostaje natywne, tekst ukryty,
   kropki odzwierciedlają długość wpisanego PIN-u (min. 6 kółek). */
function renderPinDots() {
  const inp = $("lock-pin"), box = $("pin-dots"); if (!inp || !box) return;
  const n = inp.value.length, total = Math.max(6, n);
  let h = ""; for (let i = 0; i < total; i++) h += `<i class="${i < n ? "on" : ""}"></i>`;
  box.innerHTML = h;
}
$("lock-pin").addEventListener("input", renderPinDots);

/* --- reset PIN-u z ekranu logowania --- */
/* (1) kod odzyskiwania: ustaw nowy PIN samodzielnie i zaloguj się */
async function recoverWithCode(code, newPin) {
  const norm = normalizeRecovery(code);
  for (const acc of (S.config ? S.config.accounts : [])) {
    if (!acc.active || !acc.recSalt || !acc.recWrap) continue;
    let dekRaw;
    try {
      const kek = await deriveKEK(norm, acc.recSalt);
      dekRaw = await decryptBytes(kek, acc.recWrap);
    } catch { continue; }
    // kod pasuje do tego konta — ustaw nowy PIN i zaloguj
    S.dekRaw = dekRaw;
    const wrapped = await wrapDEKWith(newPin, dekRaw);
    acc.salt = wrapped.salt; acc.wrap = wrapped.wrap; acc.fails = 0; acc.lockUntil = 0;
    await saveConfig(); scheduleSync();
    S.key = await importDEK(dekRaw);
    S.user = acc;
    S.vault = await decryptJSON(S.key, await metaGet("vault"));
    if (normalizeVault(S.vault)) await saveVault();
    await recordLogin(acc, "odzyskiwanie kodem");
    await loadRecords();
    return acc;
  }
  return null;
}

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
  // mapa wysłanych kopii (do plakietki „WYSŁANO" na liście)
  try {
    const ob = await getAll("outbox");
    S.sentIds = new Set(ob.filter(o => o.sentAt || /^wys[łl]ano|udost/i.test(o.status || "")).map(o => o.id));
  } catch { S.sentIds = new Set(); }
}

/* ===================== Role w UI ===================== */
function applyRole() {
  if (!S.user) return;
  document.querySelectorAll(".admin-only").forEach(el => { el.style.display = isAdmin() ? "" : "none"; });
  const ub = $("user-badge");
  ub.textContent = S.user.role === "support" ? "SUPPORT" : isAdmin() ? "ADMIN" : roleLabel(S.user.role).toUpperCase();
  ub.title = S.user.name + " · " + roleLabel(S.user.role);
  const un = $("user-name"); if (un) un.textContent = S.user.name || "";
}

/* ===================== Ekran główny ===================== */
function enterHome() {
  resetLockTimer();
  applyRole();
  const projs = allowedProjects();
  const sel = $("project-select");
  if (!projs.length) {
    // brak projektów — wyszarzone, „Nowa zgoda" niedostępna
    sel.innerHTML = `<option disabled selected>Brak projektów${isAdmin() ? " — dotknij „＋ Utwórz projekt”" : " — poproś administratora"}</option>`;
    sel.disabled = true;
    $("btn-new").disabled = true;
  } else {
    sel.disabled = false; $("btn-new").disabled = false;
    if (!projs.find(p => p.id === S.vault.activeProjectId)) S.vault.activeProjectId = projs[0].id;
    sel.innerHTML = projs.map(p => `<option value="${p.id}" ${p.id === S.vault.activeProjectId ? "selected" : ""}>${esc(p.name)}</option>`).join("");
  }
  { const ap = activeProject(); $("home-producer").textContent = (ap ? projectAdmin(ap) : defaultAdmin() || {}).name || S.vault.producer; }
  renderStats(); renderList($("search").value);
  $("verify-result").hidden = true;
  updateSyncBadge();
  updateCloudWarning();
  flushOutbox();
  show("view-home");
}
$("btn-new-project").addEventListener("click", () => { if (isAdmin()) { enterSettings(); setTimeout(() => { const g = $("grp-org"); if (g) g.open = true; const i = $("new-project-name"); if (i) { i.scrollIntoView({ block: "center" }); i.focus(); } }, 100); } });
/* Banner ostrzegawczy na pulpicie: pokazuje się tylko adminowi, gdy kopia w chmurze jest wyłączona. Klik prowadzi do ustawień chmury. */
function updateCloudWarning() {
  const el = $("cloud-warning");
  if (el) el.hidden = !(isAdmin() && !cloudEnabled());
}
$("cloud-warning").addEventListener("click", () => {
  enterSettings();
  setTimeout(() => { const g = $("grp-cloud"); if (g) g.open = true; const i = $("fb-password"); if (i) { i.scrollIntoView({ block: "center" }); i.focus(); } }, 100);
});
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
  // tylko aktywne, ważne zgody (cofnięte nie liczą się jako "podpisane")
  const active = rs.filter(r => r.status === "active");
  const todayStr = new Date().toLocaleDateString("pl-PL");
  const dzis = active.filter(r => r.createdAt && new Date(r.createdAt).toLocaleDateString("pl-PL") === todayStr).length;
  // ile z aktywnych zgód jest bezpiecznie w kopii E2E w chmurze
  const wChmurze = active.filter(r => isBackedUp(r)).length;
  $("home-stats").innerHTML =
    `<div class="stat"><b>${active.length}</b><span>podpisane</span></div>` +
    `<div class="stat"><b>${dzis}</b><span>dziś</span></div>` +
    `<div class="stat"><b>${wChmurze}</b><span>w chmurze</span></div>`;
}
function renderList(filter) {
  const list = $("records-list");
  const f = (filter || "").toLowerCase();
  let items = projectRecords().filter(r => !f || (!r.corrupted && (`${r.person.first} ${r.person.last}`.toLowerCase().includes(f))));
  if (!S.sortBy) S.sortBy = "date";
  items = [...items].sort((a, b) => S.sortBy === "name"
    ? ((a.person && a.person.last || "").localeCompare((b.person && b.person.last) || "", "pl") || ((a.person && a.person.first) || "").localeCompare((b.person && b.person.first) || "", "pl"))
    : ((b.createdAt || "").localeCompare(a.createdAt || "")));
  if (S.selectMode === undefined) S.selectMode = false;
  if (!S.selected) S.selected = new Set();
  const selectable = items.filter(r => !r.corrupted);
  list.innerHTML = "";

  // nagłówek sekcji + przełącznik trybu zaznaczania (wg wzorca)
  const head = document.createElement("div");
  head.className = "list-head";
  head.innerHTML = `<span class="list-head-title">OSTATNIE ZGODY</span>`;
  const right = document.createElement("div");
  right.className = "list-head-right";
  if (selectable.length || filter) {
    const seg = document.createElement("div");
    seg.className = "sortseg";
    seg.innerHTML = `<button data-s="date" class="${S.sortBy === "date" ? "on" : ""}">Data</button><button data-s="name" class="${S.sortBy === "name" ? "on" : ""}">Nazwisko</button>`;
    seg.querySelectorAll("button").forEach(b => b.addEventListener("click", () => { S.sortBy = b.dataset.s; renderList($("search").value); }));
    right.appendChild(seg);
  }
  if (selectable.length) {
    const tg = document.createElement("button");
    tg.className = "btn-selmode";
    tg.textContent = S.selectMode ? "Gotowe" : "✓ Zaznacz";
    tg.addEventListener("click", () => { S.selectMode = !S.selectMode; if (!S.selectMode) S.selected.clear(); renderList($("search").value); });
    right.appendChild(tg);
  }
  head.appendChild(right);
  list.appendChild(head);
  // legenda statusu kopii w chmurze
  if (selectable.length) {
    const lg = document.createElement("div");
    lg.className = "list-legend";
    lg.innerHTML = fbCfg()
      ? `<span class="lg dot-ok">w chmurze (odwracalne)</span><span class="lg dot-no">brak kopii</span>`
      : `<span class="lg dot-no">chmura wyłączona — żadna zgoda nie ma kopii (usunięcie nieodwracalne)</span>`;
    list.appendChild(lg);
  }

  // pasek akcji zbiorczych
  if (S.selectMode && selectable.length) {
    const allOn = S.selected.size === selectable.length;
    const bar = document.createElement("div");
    bar.className = "bulk-bar";
    bar.innerHTML = `<div class="bulk-row">
        <button class="bulk-all"><span class="rec-cb ${allOn ? "on" : ""}">${allOn ? "✓" : ""}</span>${allOn ? "Odznacz wszystkie" : "Zaznacz wszystkie"}</button>
        <span class="bulk-count">${S.selected.size} zaznaczone</span>
      </div>
      <div class="bulk-actions">
        <button class="btn bulk-send">↗ Wyślij</button>
        <button class="btn bulk-dl">↓ Pobierz</button>
        ${isAdmin() ? '<button class="btn danger bulk-del">🗑 Usuń</button>' : ""}
      </div>`;
    bar.querySelector(".bulk-all").addEventListener("click", () => {
      if (allOn) S.selected.clear(); else selectable.forEach(r => S.selected.add(r.id));
      renderList($("search").value);
    });
    bar.querySelector(".bulk-send").addEventListener("click", async () => {
      const chosen = selectable.filter(r => S.selected.has(r.id));
      if (!chosen.length) return uiAlert("Najpierw zaznacz zgody.");
      for (const r of chosen) { try { await sharePDF(r); } catch {} }
    });
    bar.querySelector(".bulk-dl").addEventListener("click", async () => {
      const chosen = selectable.filter(r => S.selected.has(r.id));
      if (!chosen.length) return uiAlert("Najpierw zaznacz zgody.");
      for (const r of chosen) { try { await downloadPDF(r); } catch {} await new Promise(res => setTimeout(res, 400)); }
    });
    const bdel = bar.querySelector(".bulk-del");
    if (bdel) bdel.addEventListener("click", async () => {
      const chosen = selectable.filter(r => S.selected.has(r.id));
      if (!chosen.length) return uiAlert("Najpierw zaznacz zgody do usunięcia.");
      await deleteRecords(chosen);
    });
    list.appendChild(bar);
  }

  if (!items.length) {
    const e = document.createElement("div"); e.className = "empty";
    e.textContent = `Brak zgód${f ? " dla tego filtra" : " w tym projekcie"}. Dotknij „＋ Nowa zgoda”.`;
    list.appendChild(e); return;
  }

  for (const r of [...items].reverse()) {
    const div = document.createElement("div");
    div.className = "record";
    if (r.corrupted) {
      div.innerHTML = `<div class="rec-avatar err">⚠</div><div class="who"><b>⚠ Rekord nieodczytywalny</b><span>${esc(r.id)}</span></div><span class="badge revoked">błąd</span>`;
      list.appendChild(div); continue;
    }
    const d = new Date(r.createdAt).toLocaleString("pl-PL");
    const revoked = r.status !== "active";
    const sent = S.sentIds && S.sentIds.has(r.id);
    const checked = S.selected.has(r.id);
    const backed = isBackedUp(r);
    div.classList.add(backed ? "rec-backed" : "rec-nobackup");
    const pills = [
      `<span class="spill ok">✓ PODPISANO</span>`,
      sent ? `<span class="spill sent">↗ WYSŁANO</span>` : "",
      backed ? `<span class="spill cloud">☁ w chmurze</span>` : `<span class="spill nocloud">☁ brak kopii</span>`,
      revoked ? `<span class="spill warn">RODO COFNIĘTA</span>` : "",
      r.person.isMinor ? `<span class="spill mut">MAŁOLETNI</span>` : "",
    ].join("");
    const cb = S.selectMode ? `<div class="rec-cb ${checked ? "on" : ""}">${checked ? "✓" : ""}</div>` : "";
    const avatar = `<div class="rec-avatar ${revoked ? "warn" : "ok"}">${revoked ? "↺" : "✓"}</div>`;
    const actions = `<div class="rec-actions">
      <button class="rec-act" data-act="send" aria-label="Wyślij kopię"><svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M22 3L11 14M22 3l-7 19-4-8-8-4 19-7z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg></button>
      <button class="rec-act" data-act="dl" aria-label="Pobierz PDF"><svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M12 3v12m0 0l-4-4m4 4l4-4M5 21h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
    </div>`;
    div.innerHTML = `${cb}${avatar}<div class="who"><b>${esc(r.person.first)} ${esc(r.person.last)}</b><span>${esc(r.person.role || "—")} · ${d}${r.operator ? " · zebrał(a): " + esc(r.operator) : ""}</span><div class="spills">${pills}</div></div>${actions}`;
    div.querySelector("[data-act=send]").addEventListener("click", (e) => { e.stopPropagation(); sharePDF(r); });
    div.querySelector("[data-act=dl]").addEventListener("click", (e) => { e.stopPropagation(); downloadPDF(r); });
    div.addEventListener("click", () => {
      if (S.selectMode) {
        if (S.selected.has(r.id)) S.selected.delete(r.id); else S.selected.add(r.id);
        renderList($("search").value);
      } else showDetail(r.id);
    });
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
    if (!await uiConfirm(`Przywrócić kopię z ${new Date(data.exportedAt).toLocaleString("pl-PL")}?\n\nUWAGA: zastąpi WSZYSTKIE obecne dane (${(data.records || []).length} rekordów w kopii). Zalogujesz się PIN-em konta z chwili wykonania kopii.`)) return;
    await applyBackup(data);
    await uiAlert("Kopia przywrócona. Zaloguj się ponownie.");
    location.reload();
  } catch (ex) { uiAlert("Błąd importu: " + ex.message); }
  finally { e.target.value = ""; }
});

/* --- synchronizacja z chmurą (E2E — wysyłamy wyłącznie zaszyfrowane pakiety) --- */
function syncCfg() { return (S.vault && S.vault.sync) || { url: "", key: "", auto: true }; }
function mailCfg() { return (S.vault && S.vault.mail) || null; }
function smtpAutodetect(email) {
  const dom = (String(email).split("@")[1] || "").toLowerCase();
  const map = {
    "gmail.com": ["smtp.gmail.com", 465], "googlemail.com": ["smtp.gmail.com", 465],
    "offhandfilms.com": ["smtp.gmail.com", 465],
    "outlook.com": ["smtp-mail.outlook.com", 587], "hotmail.com": ["smtp-mail.outlook.com", 587],
    "live.com": ["smtp-mail.outlook.com", 587], "office365.com": ["smtp.office365.com", 587],
    "yahoo.com": ["smtp.mail.yahoo.com", 465],
    "wp.pl": ["smtp.wp.pl", 465], "o2.pl": ["poczta.o2.pl", 465], "tlen.pl": ["smtp.wp.pl", 465],
    "interia.pl": ["poczta.interia.pl", 587], "onet.pl": ["smtp.poczta.onet.pl", 465],
    "op.pl": ["smtp.poczta.onet.pl", 465], "poczta.onet.pl": ["smtp.poczta.onet.pl", 465], "gazeta.pl": ["smtp.gazeta.pl", 465],
  };
  return map[dom] || null;
}
function buildSmtp() {
  const m = mailCfg();
  if (!m || !m.email || !m.pass) return null;
  let host = (m.host || "").trim(), port = m.port;
  if (!host) { const a = smtpAutodetect(m.email); if (a) { host = a[0]; if (!port) port = a[1]; } }
  if (!host) return null;
  return { host, port: Number(port) || 465, user: m.email, pass: m.pass, from: (m.from ? `${m.from} <${m.email}>` : m.email) };
}
/* Nadawca pochodzi z aplikacji (adres + hasło aplikacji wpisane przez administratora).
   Zwraca fragment treści żądania { smtp } albo null, gdy nadawca nie jest skonfigurowany. */
function mailOutgoing() {
  const s = buildSmtp();
  return s ? { smtp: s } : null;
}
function mailEnabled() { return !!mailOutgoing(); }
/* Wysyła kod odzyskiwania na adres(y) administratora, żeby nikt nie musiał go pamiętać.
   Zwraca listę adresów (string) przy sukcesie albo null, gdy maile niedostępne. */
async function emailRecoveryCode(code, accName) {
  const out = mailOutgoing();
  if (!out || !navigator.onLine) return null;
  const tos = adminEmails();
  if (!tos.length) return null;
  try {
    const resp = await fetch(FN_EMAIL_URL, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        to: tos.join(", "),
        subject: `SignOff — kod odzyskiwania (${accName})`,
        text: `Kod odzyskiwania dla konta „${accName}":\n\n    ${code}\n\n` +
          `Zachowaj tę wiadomość — nie musisz nic zapisywać.\n` +
          `Gdy zapomnisz PIN-u: ekran logowania → „Nie pamiętam PIN-u" → wpisz ten kod i ustaw nowy PIN.\n\n` +
          `Kto ma ten kod, może zresetować PIN tego konta — nie przekazuj go dalej.\n\n` +
          `(Wiadomość automatyczna z aplikacji SignOff by Offhand.)`,
        ...out,
      }),
    });
    return resp.ok ? tos.join(", ") : null;
  } catch { return null; }
}
/* ===================== Firebase Firestore (chmura, REST — bez SDK) =====================
   Zaszyfrowana kopia (E2E) trzymana w Firestore. Duży backup dzielony na fragmenty
   (limit 1 MB/dokument): metadane w kolekcji „signoff", fragmenty w „signoff_chunks". */
function fbCfg() { const f = S.vault && S.vault.fb; return (f && f.enabled && f.apiKey && f.projectId && f.email && f.password) ? f : null; }
let fbToken = null, fbTokenAt = 0;
async function fbSignIn() {
  const c = fbCfg(); if (!c) throw new Error("Brak konfiguracji Firebase.");
  if (fbToken && Date.now() - fbTokenAt < 50 * 60 * 1000) return fbToken;
  const resp = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(c.apiKey)}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: c.email, password: c.password, returnSecureToken: true }),
  });
  const out = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error((out.error && out.error.message) || "logowanie Firebase nieudane");
  fbToken = out.idToken; fbTokenAt = Date.now();
  return fbToken;
}
function fbDocUrl(c, path) { return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(c.projectId)}/databases/(default)/documents/${path}`; }
const FB_CHUNK = 700000;
async function fbUpload(rec) {
  const c = fbCfg(), token = await fbSignIn();
  const H = { Authorization: "Bearer " + token, "Content-Type": "application/json" };
  const json = JSON.stringify(rec.payload);
  const parts = []; for (let i = 0; i < json.length; i += FB_CHUNK) parts.push(json.slice(i, i + FB_CHUNK));
  for (let i = 0; i < parts.length; i++) {
    const r = await fetch(fbDocUrl(c, `signoff_chunks/${rec.deviceId}_${i}`), { method: "PATCH", headers: H, body: JSON.stringify({ fields: { data: { stringValue: parts[i] } } }) });
    if (!r.ok) { const o = await r.json().catch(() => ({})); throw new Error((o.error && o.error.message) || ("zapis fragmentu " + r.status)); }
  }
  const m = await fetch(fbDocUrl(c, `signoff/${rec.deviceId}`), { method: "PATCH", headers: H, body: JSON.stringify({ fields: { deviceName: { stringValue: rec.deviceName || "" }, updatedAt: { stringValue: rec.updatedAt }, chunks: { integerValue: String(parts.length) } } }) });
  if (!m.ok) { const o = await m.json().catch(() => ({})); throw new Error((o.error && o.error.message) || ("zapis metadanych " + m.status)); }
  for (let i = parts.length; i < parts.length + 10; i++) fetch(fbDocUrl(c, `signoff_chunks/${rec.deviceId}_${i}`), { method: "DELETE", headers: H }).catch(() => {});
  return true;
}
async function fbDownload(deviceId) {
  const c = fbCfg(), token = await fbSignIn();
  const H = { Authorization: "Bearer " + token };
  const meta = await (await fetch(fbDocUrl(c, `signoff/${deviceId}`), { headers: H })).json();
  const n = meta.fields && meta.fields.chunks ? Number(meta.fields.chunks.integerValue) : 0;
  let json = "";
  for (let i = 0; i < n; i++) {
    const r = await fetch(fbDocUrl(c, `signoff_chunks/${deviceId}_${i}`), { headers: H });
    const o = await r.json(); if (!r.ok) throw new Error("pobranie fragmentu " + i);
    json += o.fields.data.stringValue;
  }
  return { deviceId, payload: JSON.parse(json) };
}
async function fbListDevices() {
  const c = fbCfg(), token = await fbSignIn();
  const resp = await fetch(fbDocUrl(c, `signoff`), { headers: { Authorization: "Bearer " + token } });
  const out = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error((out.error && out.error.message) || ("lista " + resp.status));
  return (out.documents || []).map(d => {
    const id = (d.name || "").split("/").pop();
    const f = d.fields || {};
    return { deviceId: id, deviceName: (f.deviceName && f.deviceName.stringValue) || id, updatedAt: f.updatedAt && f.updatedAt.stringValue };
  });
}
/* --- Wspólny rejestr logowań (zaszyfrowany E2E) — dopisywanie i czytanie ze wszystkich urządzeń --- */
async function fbPushLogin(entry) {
  const c = fbCfg(); if (!c || !S.key) return;
  const token = await fbSignIn();
  const payload = { at: entry.at, name: entry.name, role: entry.role, device: entry.device, kind: entry.kind, geo: entry.geo || null, geoBlocked: !!entry.geoBlocked, deviceId: (S.config && S.config.deviceId) || "" };
  const enc = await encryptJSON(S.key, payload); // {iv, ct} — Google widzi tylko szyfrogram
  const id = `${(S.config && S.config.deviceId) || "dev"}__${(entry.at || "").replace(/[^0-9]/g, "")}`;
  const body = { fields: { at: { stringValue: entry.at || "" }, p: { stringValue: JSON.stringify(enc) } } };
  const r = await fetch(fbDocUrl(c, `signoff_logins/${id}`), { method: "PATCH", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error("push login " + r.status);
}
async function fbListLogins() {
  const c = fbCfg(); if (!c || !S.key) return [];
  const token = await fbSignIn();
  const resp = await fetch(fbDocUrl(c, `signoff_logins?pageSize=300`), { headers: { Authorization: "Bearer " + token } });
  const out = await resp.json().catch(() => ({}));
  if (!resp.ok) return [];
  const res = [];
  for (const d of (out.documents || [])) {
    const f = d.fields || {};
    if (f.p && f.p.stringValue) { try { res.push(await decryptJSON(S.key, JSON.parse(f.p.stringValue))); } catch {} }
  }
  return res;
}

/* --- A+B: niezmienialna historia kopii — każda migawka to osobny, NIENADPISYWALNY wpis.
   Reguły Firestore zabraniają update/delete na signoff_history*, więc backupu nie da się
   skasować ani zepsuć nadpisaniem. Migawkę robimy max raz na ~20 h oraz przy ręcznej sync. */
async function fbSnapshotHistory(rec) {
  const c = fbCfg(), token = await fbSignIn();
  const H = { Authorization: "Bearer " + token, "Content-Type": "application/json" };
  const base = `${rec.deviceId}__${rec.updatedAt.replace(/[^0-9]/g, "")}`;
  const json = JSON.stringify(rec.payload);
  const parts = []; for (let i = 0; i < json.length; i += FB_CHUNK) parts.push(json.slice(i, i + FB_CHUNK));
  for (let i = 0; i < parts.length; i++) {
    const r = await fetch(fbDocUrl(c, `signoff_history_chunks/${base}_${i}`), { method: "PATCH", headers: H, body: JSON.stringify({ fields: { data: { stringValue: parts[i] } } }) });
    if (!r.ok) { const o = await r.json().catch(() => ({})); throw new Error((o.error && o.error.message) || ("zapis fragmentu historii " + r.status)); }
  }
  const m = await fetch(fbDocUrl(c, `signoff_history/${base}`), { method: "PATCH", headers: H, body: JSON.stringify({ fields: { deviceId: { stringValue: rec.deviceId }, deviceName: { stringValue: rec.deviceName || "" }, updatedAt: { stringValue: rec.updatedAt }, chunks: { integerValue: String(parts.length) } } }) });
  if (!m.ok) { const o = await m.json().catch(() => ({})); throw new Error((o.error && o.error.message) || ("zapis metadanych historii " + m.status)); }
  return true;
}
async function fbListHistory() {
  const c = fbCfg(), token = await fbSignIn();
  const resp = await fetch(fbDocUrl(c, `signoff_history?pageSize=300`), { headers: { Authorization: "Bearer " + token } });
  const out = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error((out.error && out.error.message) || ("lista historii " + resp.status));
  return (out.documents || []).map(d => {
    const id = (d.name || "").split("/").pop(); const f = d.fields || {};
    return { id, deviceName: (f.deviceName && f.deviceName.stringValue) || id, updatedAt: f.updatedAt && f.updatedAt.stringValue };
  }).sort((a, b) => (b.updatedAt || "").localeCompare(a.updatedAt || ""));
}
async function fbDownloadHistory(id) {
  const c = fbCfg(), token = await fbSignIn();
  const H = { Authorization: "Bearer " + token };
  const meta = await (await fetch(fbDocUrl(c, `signoff_history/${id}`), { headers: H })).json();
  const n = meta.fields && meta.fields.chunks ? Number(meta.fields.chunks.integerValue) : 0;
  let json = "";
  for (let i = 0; i < n; i++) {
    const r = await fetch(fbDocUrl(c, `signoff_history_chunks/${id}_${i}`), { headers: H });
    const o = await r.json(); if (!r.ok) throw new Error("pobranie fragmentu historii " + i);
    json += o.fields.data.stringValue;
  }
  return { payload: JSON.parse(json) };
}
/* Domyślny adres serwera wysyłki e-mail (Render) — żeby maile działały bez ręcznego wpisywania adresu. */
/* Adres Cloud Function wysyłającej maile (Firebase, region europe-west1).
   Region/projekt muszą zgadzać się z deployem funkcji w functions/index.js. */
const FN_EMAIL_URL = "https://europe-west1-signoff-offhand.cloudfunctions.net/sendEmail";

function cloudEnabled() { return !!fbCfg() || !!(syncCfg().url && syncCfg().key); }

/* dane projektu Firebase signoff-offhand (apiKey/projectId są jawne; hasło wpisuje administrator) */
const FB_DEFAULTS = { apiKey: "AIzaSyCRx_G6RBTxazAismxKuu2WkYNvsJ8FJJU", projectId: "signoff-offhand", email: "signoff-sync@offhand.app" };
$("btn-fb-save").addEventListener("click", async () => {
  const st = $("fb-status");
  const enabled = $("fb-enabled").checked, password = $("fb-password").value;
  if (enabled && !password) { st.textContent = "🛑 Wpisz hasło konta technicznego."; return; }
  S.vault.fb = {
    enabled, password,
    apiKey: $("fb-apikey").value.trim() || FB_DEFAULTS.apiKey,
    projectId: $("fb-projectid").value.trim() || FB_DEFAULTS.projectId,
    email: $("fb-email").value.trim() || FB_DEFAULTS.email,
    auto: $("fb-auto").checked,
  };
  fbToken = null;
  await saveVault();
  if (!enabled) { st.textContent = "Kopia w chmurze wyłączona."; updateSyncBadge(); return; }
  st.textContent = "Łączę z Firebase i wysyłam testową kopię…";
  const ok = await syncPush(true);
  if (ok) { st.textContent = "✅ Połączono. Kopia w chmurze (Firebase) działa."; updateSyncBadge(); }
  else { st.textContent = ($("sync-status").textContent || "").replace("synchronizacji", "połączenia z Firebase") || "🛑 Nie udało się — sprawdź hasło."; }
});
$("btn-fb-restore").addEventListener("click", async () => {
  const box = $("fb-restore-list");
  if (!fbCfg()) { box.innerHTML = '<p class="error">Najpierw włącz Firebase i zapisz (z hasłem).</p>'; return; }
  box.innerHTML = "Pobieram listę kopii z chmury…";
  try {
    const devices = await fbListDevices();
    if (!devices.length) { box.innerHTML = '<p class="tiny muted">Brak kopii w chmurze.</p>'; return; }
    box.innerHTML = "";
    for (const d of devices) {
      const row = document.createElement("div");
      row.className = "attach-row";
      row.innerHTML = `<div class="attach-info">💾 <b>${esc(d.deviceName)}</b> <span class="tiny muted">${d.updatedAt ? new Date(d.updatedAt).toLocaleString("pl-PL") : ""}${d.deviceId === S.config.deviceId ? " · (to urządzenie)" : ""}</span></div><button class="btn">⬇ Przywróć</button>`;
      row.querySelector("button").addEventListener("click", async () => {
        if (!await uiConfirm(`Przywrócić kopię „${d.deviceName}”?\n\nZastąpi WSZYSTKIE dane na tym urządzeniu.`)) return;
        try { const data = await fbDownload(d.deviceId); await applyBackup(data.payload); await uiAlert("Kopia przywrócona. Zaloguj się ponownie."); location.reload(); }
        catch (e) { uiAlert("Błąd przywracania: " + e.message); }
      });
      box.appendChild(row);
    }
    // A+B: niezmienialna historia kopii (nie do skasowania ani nadpisania)
    try {
      const hist = await fbListHistory();
      if (hist.length) {
        const h = document.createElement("p");
        h.className = "tiny muted"; h.style.marginTop = "14px";
        h.textContent = `🛡 Niezmienialna historia kopii (${hist.length}) — nie da się jej skasować ani nadpisać:`;
        box.appendChild(h);
        for (const v of hist) {
          const row = document.createElement("div");
          row.className = "attach-row";
          row.innerHTML = `<div class="attach-info">🕘 <span class="tiny muted">${v.updatedAt ? new Date(v.updatedAt).toLocaleString("pl-PL") : esc(v.id)}</span></div><button class="btn">⬇ Przywróć</button>`;
          row.querySelector("button").addEventListener("click", async () => {
            if (!await uiConfirm(`Przywrócić kopię z ${v.updatedAt ? new Date(v.updatedAt).toLocaleString("pl-PL") : v.id}?\n\nZastąpi WSZYSTKIE dane na tym urządzeniu.`)) return;
            try { const data = await fbDownloadHistory(v.id); await applyBackup(data.payload); await uiAlert("Kopia przywrócona. Zaloguj się ponownie."); location.reload(); }
            catch (e) { uiAlert("Błąd przywracania: " + e.message); }
          });
          box.appendChild(row);
        }
      }
    } catch (e) { /* brak historii / brak uprawnień — nie blokuje listy urządzeń */ }
  } catch (e) { box.innerHTML = `<p class="error">Błąd: ${esc(e.message)}</p>`; }
});

function updateSyncBadge(msg) {
  const b = $("sync-badge");
  if (!b) return;
  if (!cloudEnabled()) { b.textContent = "☁ wyłączona"; b.className = "hb-sync off"; b.title = "Kopia w chmurze wyłączona"; return; }
  if (msg === "błąd") { b.textContent = "☁ błąd zapisu"; b.className = "hb-sync err"; b.title = "Ostatnia kopia się nie zapisała — spróbuję ponownie automatycznie"; return; }
  if (!navigator.onLine) { b.textContent = "☁ offline"; b.className = "hb-sync wait"; b.title = "Brak internetu — kopia wyśle się po połączeniu"; return; }
  if (msg === "wysyłanie…") { b.textContent = "☁ zapis…"; b.className = "hb-sync ok"; b.title = "Zapisywanie kopii w chmurze…"; return; }
  // połączona — stały zielony
  const t = S.config && S.config.lastSync ? new Date(S.config.lastSync).toLocaleTimeString("pl-PL", { hour: "2-digit", minute: "2-digit" }) : null;
  b.textContent = "☁ połączono";
  b.className = "hb-sync ok";
  b.title = t ? ("Połączono z chmurą · ostatnia kopia o " + t) : "Połączono z chmurą";
}
async function syncPush(manual) {
  const fb = fbCfg(), c = syncCfg();
  if (!fb && (!c.url || !c.key)) { if (manual) uiAlert("Skonfiguruj chmurę (Firebase) w ustawieniach."); return false; }
  if (!navigator.onLine) { updateSyncBadge("offline — wyśle po połączeniu"); return false; }
  try {
    updateSyncBadge("wysyłanie…");
    const payload = await buildBackup();
    const rec = { deviceId: S.config.deviceId, deviceName: S.config.deviceName, updatedAt: new Date().toISOString(), payload };
    if (fb) {
      await fbUpload(rec);
      S.config.lastSync = rec.updatedAt;
      // A+B: niezmienialna migawka (ręcznie zawsze, automatycznie max raz na ~20 h)
      const lastSnap = S.config.lastSnapshot ? Date.parse(S.config.lastSnapshot) : 0;
      if (manual || !lastSnap || Date.now() - lastSnap > 20 * 60 * 60 * 1000) {
        try { await fbSnapshotHistory(rec); S.config.lastSnapshot = rec.updatedAt; } catch (e) { /* historia nie blokuje bieżącej kopii */ }
      }
    } else {
      const resp = await fetch(c.url.replace(/\/+$/, "") + "/api/sync", { method: "POST", headers: { "Content-Type": "application/json", "X-Sync-Key": c.key }, body: JSON.stringify(rec) });
      const out = await resp.json(); if (!resp.ok) throw new Error(out.error || resp.status);
      S.config.lastSync = out.updatedAt;
    }
    await saveConfig();
    updateSyncBadge();
    if (manual) $("sync-status").textContent = `✅ Zsynchronizowano${fb ? " (Firebase)" : ""}: ` + new Date(S.config.lastSync).toLocaleString("pl-PL");
    return true;
  } catch (e) {
    updateSyncBadge("błąd");
    if (manual) $("sync-status").textContent = "🛑 Błąd synchronizacji: " + e.message;
    return false;
  }
}
function scheduleSync() {
  const c = syncCfg();
  if (fbCfg() && (S.vault.fb.auto !== false) && S.key) { clearTimeout(S.syncTimer); S.syncTimer = setTimeout(() => syncPush(false), 2500); return; }
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
        if (!await uiConfirm(`Przywrócić kopię „${d.deviceName}” z ${new Date(d.updatedAt).toLocaleString("pl-PL")}?\n\nZastąpi WSZYSTKIE dane na tym urządzeniu.`)) return;
        const r2 = await fetch(c.url.replace(/\/+$/, "") + "/api/sync?device=" + encodeURIComponent(d.deviceId), { headers: { "X-Sync-Key": c.key } });
        const data = await r2.json();
        if (!r2.ok) { uiAlert("Błąd: " + (data.error || r2.status)); return; }
        await applyBackup(data.payload);
        await uiAlert("Kopia przywrócona. Zaloguj się ponownie.");
        location.reload();
      });
      box.appendChild(row);
    }
  } catch (e) { box.innerHTML = `<p class="error">Błąd: ${esc(e.message)}</p>`; }
});

/* ===================== Pliki projektu (PDF do podpisu) ===================== */
const MAX_CONTENT_FILE = 15 * 1024 * 1024;
/* Zapisuje treść-plik (PDF, a Word .docx konwertuje do PDF) do zaszyfrowanego magazynu.
   Zwraca metadane pozycji typu „pdf" — bez przypisania do projektu. */
async function addContentFile(file) {
  const lower = (file.name || "").toLowerCase();
  if (file.size > MAX_CONTENT_FILE) throw new Error("Plik przekracza 15 MB.");
  let buf, name = file.name;
  if (file.type === "application/pdf" || lower.endsWith(".pdf")) {
    buf = await file.arrayBuffer();
  } else if (lower.endsWith(".docx")) {
    let paras;
    try { paras = await docxToParagraphs(await file.arrayBuffer()); }
    catch { throw new Error("Nie udało się odczytać pliku Word. Zapisz go w Wordzie jako PDF i wgraj PDF."); }
    if (!paras.some(p => p.trim())) throw new Error("Plik Word wygląda na pusty lub nieobsługiwany. Zapisz jako PDF i wgraj PDF.");
    buf = await paragraphsToPdfBytes(paras, file.name.replace(/\.docx$/i, ""));
    name = file.name.replace(/\.docx$/i, ".pdf");
  } else {
    throw new Error("Obsługiwane pliki: PDF lub Word (.docx). Stary .doc zapisz w Wordzie jako PDF.");
  }
  const hash = await sha256hex(buf);
  let pages = 0;
  try { pages = (await window.PDFLib.PDFDocument.load(buf)).getPageCount(); } catch {}
  const fileId = uuid();
  const pack = await encryptBytes(S.key, buf);
  await tx("files", "readwrite", s => s.put({ id: fileId, pack }));
  return { fileId, fileName: name, size: buf.byteLength, pages, hash, type: "pdf" };
}
async function openFile(fileMeta) {
  const id = fileMeta.fileId || fileMeta.id;
  const row = await storeGet("files", id);
  if (!row) { uiAlert("Nie znaleziono pliku w magazynie."); return; }
  const buf = await decryptBytes(S.key, row.pack);
  const url = URL.createObjectURL(new Blob([buf], { type: "application/pdf" }));
  window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

/* ---- Word (.docx) → tekst → PDF (offline, bez nowych zależności) ---- */
function decodeXmlEntities(s) {
  return String(s)
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&amp;/g, "&");
}
async function inflateRaw(u8) {
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Response(new Blob([u8])).body.pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
/* Wyciąga jeden wpis z archiwum ZIP (przez centralny katalog). Zwraca tekst albo null. */
async function unzipEntryText(arrayBuffer, wantName) {
  const u8 = new Uint8Array(arrayBuffer);
  const dv = new DataView(arrayBuffer);
  let eocd = -1;
  for (let i = u8.length - 22; i >= 0 && i >= u8.length - 22 - 65536; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("ZIP: brak EOCD");
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  for (let n = 0; n < count; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const compSize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const lhOffset = dv.getUint32(p + 42, true);
    const name = td.decode(u8.subarray(p + 46, p + 46 + nameLen));
    if (name === wantName) {
      if (dv.getUint32(lhOffset, true) !== 0x04034b50) throw new Error("ZIP: zły nagłówek lokalny");
      const lNameLen = dv.getUint16(lhOffset + 26, true);
      const lExtraLen = dv.getUint16(lhOffset + 28, true);
      const dataStart = lhOffset + 30 + lNameLen + lExtraLen;
      const comp = u8.subarray(dataStart, dataStart + compSize);
      if (method === 0) return td.decode(comp);
      if (method === 8) return td.decode(await inflateRaw(comp));
      throw new Error("ZIP: nieobsługiwana kompresja " + method);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}
async function docxToParagraphs(arrayBuffer) {
  const xml = await unzipEntryText(arrayBuffer, "word/document.xml");
  if (!xml) throw new Error("Brak word/document.xml");
  const paras = [];
  const pRe = /<w:p\b[^>]*>([\s\S]*?)<\/w:p>/g;
  let m;
  while ((m = pRe.exec(xml))) {
    let txt = "";
    const tRe = /<w:t\b[^>]*>([\s\S]*?)<\/w:t>|<w:tab\b[^>]*\/?>|<w:br\b[^>]*\/?>/g;
    let tm;
    while ((tm = tRe.exec(m[1]))) {
      if (tm[1] !== undefined) txt += decodeXmlEntities(tm[1]);
      else if (tm[0].indexOf("<w:tab") === 0) txt += "    ";
      else txt += "\n";
    }
    paras.push(txt.replace(/\s+$/g, ""));
  }
  // usuń nadmiarowe puste akapity na początku/końcu
  while (paras.length && !paras[0].trim()) paras.shift();
  while (paras.length && !paras[paras.length - 1].trim()) paras.pop();
  return paras;
}
async function paragraphsToPdfBytes(paragraphs, title) {
  const { PDFDocument, rgb } = window.PDFLib;
  const doc = await PDFDocument.create();
  const { font, fontB } = await loadFonts(doc);
  const A4 = [595.28, 841.89], M = 50, W = A4[0] - 2 * M;
  const ink = rgb(0.06, 0.11, 0.18);
  let page = doc.addPage(A4), y = A4[1] - M;
  const ensure = (need) => { if (y - need < M) { page = doc.addPage(A4); y = A4[1] - M; } };
  const draw = (s, { size = 10, bold = false, gap = 5 } = {}) => {
    const f = bold ? fontB : font;
    const lines = s ? wrapText(s.replace(/\t/g, "    "), f, size, W) : [""];
    for (const ln of lines) { ensure(size + gap); if (ln) page.drawText(ln, { x: M, y, size, font: f, color: ink }); y -= size + gap; }
  };
  if (title) draw(title, { size: 14, bold: true, gap: 10 });
  for (const para of paragraphs) draw(para, { size: 10, gap: 5 });
  return await doc.save();
}

/* ===================== Kreator ===================== */
const STEPS = 6;
function startWizard() {
  const proj = activeProject();
  S.wizard = {
    id: uuid(), audit: [], device: deviceInfo(), geo: null,
    signature: null, photo: null, startedAt: new Date().toISOString(),
    projectId: proj.id, projectName: proj.name,
    attachChecks: {}, paid: false,
  };
  auditEvent(S.wizard, "start", `otwarto formularz zgody (projekt: ${proj.name}, zbiera: ${S.user.name} [${S.user.role}])`);
  ensureGeoPrimed().then(() => tryGeolocate(S.wizard));
  $("wizard-project-label").textContent = `Projekt: ${proj.name} · Zbiera: ${S.user.name}`;
  ["f-first", "f-last", "f-email", "f-phone", "f-doc", "f-role", "f-gfirst", "f-glast"].forEach(id => $(id).value = "");
  $("f-minor").checked = false; $("guardian-box").hidden = true;
  $("wiz-paid-no").checked = true; $("wiz-paid-yes").checked = false;
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
    // obowiązkowe zgody: zamiast czerwonego napisu — podświetlamy niezaznaczone na czerwono
    let missingConsent = false;
    ["c-image", "c-rodo"].forEach(id => {
      const cb = $(id), label = cb.closest(".big-check");
      if (!cb.checked) { if (label) label.classList.add("consent-missing"); missingConsent = true; }
      else if (label) label.classList.remove("consent-missing");
    });
    if (missingConsent) {
      const first = document.querySelector("#wstep-2 .big-check.consent-missing");
      if (first) first.scrollIntoView({ block: "center", behavior: "smooth" });
      return false;
    }
    const proj = activeProject();
    for (const it of projectDocs(proj)) {
      if (it.required !== false && !S.wizard.attachChecks[it.fileId]) { err.textContent = `Zaznacz akceptację obowiązkowego dokumentu: ${it.fileName || it.name}.`; err.hidden = false; return false; }
    }
    S.wizard.consents = { image81: true, rodo: true, marketing: $("c-marketing").checked };
    S.wizard.attachments = projectDocs(proj).map(it => ({ fileId: it.fileId, name: it.fileName || it.name, hash: it.hash, required: it.required !== false, accepted: !!S.wizard.attachChecks[it.fileId], kind: it.kind }));
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
// Renderuje treść (streszczenie + sekcje) dla wybranego wariantu bezpłatny/płatny (S.wizard.paid).
function renderConsentContent() {
  const proj = activeProject();
  const effProj = Object.assign({}, proj, { paid: !!S.wizard.paid });
  const parts = consentParts(S.vault, effProj, S.wizard.person);
  // pełna, sklejona treść do rekordu/PDF/hasza — zależna od wariantu
  S.wizard.templateText = consentText(S.vault, effProj, S.wizard.person);
  // „W skrócie” jako osobna karta (ukryta przy własnej treści projektu)
  const sum = $("consent-summary");
  if (parts.summary) { sum.textContent = parts.summary; sum.hidden = false; } else { sum.textContent = ""; sum.hidden = true; }
  // dwie sekcje treści z osobnymi polami + gradient znikający po dojechaniu do końca każdego
  const fade = (box) => {
    if (!box) return;
    const upd = () => box.classList.toggle("at-end", box.scrollHeight - box.clientHeight - box.scrollTop < 8);
    box.scrollTop = 0; box.onscroll = upd; setTimeout(upd, 0);
  };
  const imgBox = $("consent-text-image"), rodoBox = $("consent-text-rodo");
  imgBox.textContent = parts.image; fade(imgBox);
  rodoBox.textContent = parts.rodo; fade(rodoBox);
}
function prepareConsentStep() {
  const proj = activeProject();
  // wariant bezpłatny/płatny wybrany w kroku 1 (formularz) — determinuje treść tutaj
  S.wizard.paid = !!$("wiz-paid-yes").checked;
  renderConsentContent();
  auditEvent(S.wizard, "treść", `wyświetlono treść zgody (szablon ${TEMPLATE_VERSION}, udział ${S.wizard.paid ? "płatny" : "bezpłatny"}${proj.customText ? ", treść własna projektu" : ""})`);
  // zgody dostępne od razu — bez wymuszania przewijania
  ["c-image", "c-rodo", "c-marketing"].forEach(id => { const cb = $(id); cb.disabled = false; const lbl = cb.closest(".big-check"); if (lbl) lbl.classList.remove("consent-missing"); });
  $("c-image").required = true; $("c-rodo").required = true; $("c-marketing").required = false;
  // dokumenty projektu (regulaminy/umowy)
  const ab = $("attach-box");
  ab.innerHTML = "";
  S.wizard.attachChecks = {};
  for (const it of projectDocs(proj)) {
    const fname = it.fileName || it.name;
    const required = it.required !== false;
    const big = (it.pages || 0) > 10;
    const row = document.createElement("div");
    row.className = required ? "doc-accept" : "attach-row";
    row.innerHTML = `
      <div class="attach-info">📎 <b>${esc(fname)}</b>${it.desc ? ` <span class="tiny muted">${esc(it.desc)}</span>` : ""} <span class="doc-pages">${it.pages ? it.pages + " str." : ""}${required ? "" : " · do wglądu"}</span></div>
      <button class="btn" type="button" data-open>👁 Otwórz dokument</button>
      ${required ? `<label class="check"><input type="checkbox" data-acc required><span>${big ? "Potwierdzam, że zapoznałem/am się z <b>całością</b> dokumentu i akceptuję go" : "Zapoznałem/am się z dokumentem i akceptuję go"} <span class="req-star">✱ obowiązkowe</span></span></label>` : ""}`;
    row.querySelector("[data-open]").addEventListener("click", () => { openFile(it); auditEvent(S.wizard, "dokument", `otwarto: ${fname}`); });
    const cb = row.querySelector("[data-acc]");
    if (cb) cb.addEventListener("change", () => { S.wizard.attachChecks[it.fileId] = cb.checked; auditEvent(S.wizard, "dokument", `${fname}: ${cb.checked ? "zaakceptowano" : "cofnięto"}`); });
    ab.appendChild(row);
  }
  ["c-image", "c-rodo", "c-marketing"].forEach(id => {
    $(id).onchange = (e) => {
      auditEvent(S.wizard, "checkbox", `${id}: ${e.target.checked ? "zaznaczono" : "odznaczono"}`);
      const lbl = e.target.closest(".big-check");
      if (lbl && e.target.checked) lbl.classList.remove("consent-missing");
    };
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
    const name = e && e.name ? e.name : "Error";
    if (name === "NotAllowedError" || name === "SecurityError" || name === "PermissionDeniedError") {
      let state = "denied";
      try { if (navigator.permissions && navigator.permissions.query) { const p = await navigator.permissions.query({ name: "camera" }); state = p.state; } } catch {}
      showCameraHelp(state === "prompt" ? "prompt" : "denied");
    } else { showCameraHelp(name); }
  }
}
$("btn-cam-start").addEventListener("click", startCamera);
function showCameraHelp(mode) {
  document.getElementById("cam-help") && document.getElementById("cam-help").remove();
  const os = detectOS();
  let title, intro, steps = "";
  if (mode === "prompt") {
    title = "Pozwól na dostęp do aparatu";
    intro = "Telefon zaraz sam zapyta o dostęp do aparatu. Dotknij <b>Zezwól</b> (albo „OK”) — to wszystko.";
    steps = `<li>Dotknij <b>Spróbuj ponownie</b>.</li><li>Gdy pojawi się pytanie telefonu — wybierz <b>Zezwól</b>.</li>`;
  } else if (mode === "Unsupported" || mode === "NotSupportedError") {
    title = "Aparat niedostępny w tym oknie";
    intro = "Otwórz aplikację z <b>ikony na ekranie głównym</b> telefonu (nie z linku w wiadomości), pod adresem zaczynającym się od <b>https://</b>.";
    steps = `<li>Dotknij <b>Spróbuj ponownie</b>.</li>`;
  } else if (mode === "NotFoundError" || mode === "DevicesNotFoundError" || mode === "OverconstrainedError") {
    title = "Nie znaleziono aparatu";
    intro = "Aparat może być zajęty przez inną aplikację (np. Aparat, Zoom, Instagram) — zamknij ją.";
    steps = `<li>Dotknij <b>Spróbuj ponownie</b>.</li><li>Jeśli urządzenie nie ma aparatu, a zdjęcie nie jest wymagane — możesz je pominąć.</li>`;
  } else { // denied — telefon nie zapyta ponownie, trzeba włączyć w ustawieniach
    intro = "Dostęp do aparatu został wcześniej odrzucony, więc telefon już o niego nie zapyta. Trzeba <b>raz</b> go włączyć — to zajmie chwilę:";
    if (os === "ios") {
      title = "Włącz aparat w ustawieniach (iPhone / iPad)";
      steps = `<li>Otwórz <b>Ustawienia</b> telefonu → znajdź <b>SignOff</b>.</li>
        <li>Dotknij <b>Aparat</b>, aż przełącznik będzie <b>zielony</b>.</li>
        <li>Wróć tu i dotknij <b>Spróbuj ponownie</b>.</li>`;
    } else if (os === "android") {
      title = "Włącz aparat w ustawieniach (Android)";
      steps = `<li>Dotknij ikony <b>🔒 / ⓘ</b> obok adresu na górze ekranu (albo przytrzymaj ikonę SignOff → <b>Informacje o aplikacji</b>).</li>
        <li>Wejdź w <b>Uprawnienia → Aparat</b> i wybierz <b>Zezwalaj</b>.</li>
        <li>Wróć tu i dotknij <b>Spróbuj ponownie</b>.</li>`;
    } else {
      title = "Włącz aparat w przeglądarce";
      steps = `<li>Kliknij ikonę <b>kłódki / aparatu</b> w pasku adresu i ustaw aparat na <b>Zezwól</b>.</li>
        <li>Kliknij <b>Spróbuj ponownie</b>.</li>`;
    }
  }
  const ov = document.createElement("div");
  ov.id = "cam-help"; ov.className = "cam-help";
  ov.innerHTML = `<div class="cam-help-card">
    <div class="cam-help-icon">📷</div>
    <h3>${title}</h3>
    <p class="muted">${intro}</p>
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
    <tr><td>Zgoda na kontakt (przyszłe projekty / współpraca)</td><td>${w.consents.marketing ? "✅ udzielona" : "— nieudzielona"}</td></tr>
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
    const wproj = S.vault.projects.find(p => p.id === w.projectId);
    const record = {
      id: w.id, createdAt: new Date().toISOString(), startedAt: w.startedAt,
      projectId: w.projectId, projectName: w.projectName, producer: (projectAdmin(wproj) || {}).name || S.vault.producer,
      operator: S.user.name, operatorRole: S.user.role, operatorId: S.user.id,
      templateVersion: TEMPLATE_VERSION, templateText: w.templateText, paid: !!w.paid,
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
      if (syncCfg().autoEmail !== false) {
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
/* Wysyłka maila przez Firebase Cloud Function (Resend po stronie serwera —
   klucz API nigdy nie trafia do przeglądarki). Adres funkcji = FN_EMAIL_URL. */
async function serverEmail(r) {
  const out = mailOutgoing();
  if (!out || !isValidEmail(r.person.email) || !navigator.onLine) return false;
  try {
    const bytes = await buildPDF(r);
    const resp = await fetch(FN_EMAIL_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        to: r.person.email,
        subject: `Kopia podpisanej zgody — ${r.projectName}`,
        text: `Dzień dobry,\n\nw załączeniu kopia zgody podpisanej w dniu ${new Date(r.createdAt).toLocaleString("pl-PL")}.\nID dokumentu: ${r.id}\nSHA-256: ${r.hash}\n\nPozdrawiamy,\n${r.producer}`,
        filename: `zgoda-${r.person.last}-${r.person.first}.pdf`.toLowerCase().replace(/\s+/g, "-"),
        pdfBase64: b64.enc(bytes),
        ...out,
      }),
    });
    if (!resp.ok) return false;
    await markSent(r.id, "wysłano e-mailem (Firebase)");
    return true;
  } catch { return false; }
}
async function sharePDF(r) {
  if (await serverEmail(r)) { uiAlert("Kopia wysłana e-mailem przez serwer do: " + r.person.email); return; }
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
  if (flushing || c.autoEmail === false || !mailEnabled() || !navigator.onLine || !S.key) return;
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
      Przyszłe projekty / współpraca: ${r.consents.marketing ? '<span class="badge ok">tak</span>' : '<span class="badge planned">nie</span>'}</p>
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
      ${isAdmin() ? '<button class="btn danger" id="btn-del-record" data-help="Trwale usuwa tę zgodę z urządzenia. Kopia trafia do niezmienialnej historii w chmurze — można ją odtworzyć przez „Przywróć z chmury”.">🗑 Usuń zgodę</button>' : ""}
    </div>`;
  $("btn-detail-pdf").addEventListener("click", () => downloadPDF(r));
  $("btn-detail-share").addEventListener("click", () => sharePDF(r));
  const rv = $("btn-revoke");
  if (rv) rv.addEventListener("click", () => revokeRodo(r));
  const dr = $("btn-del-record");
  if (dr) dr.addEventListener("click", () => deleteRecord(r));
  show("view-detail");
}
$("btn-detail-back").addEventListener("click", enterHome);

/* Wymuszona, niezmienialna migawka stanu w chmurze — wołana PRZED usunięciem,
   żeby usunięte dane dało się odtworzyć przez „Przywróć z chmury”. */
async function snapshotNow() {
  if (!fbCfg()) return false;
  try {
    const payload = await buildBackup();
    const rec = { deviceId: S.config.deviceId, deviceName: S.config.deviceName, updatedAt: new Date().toISOString(), payload };
    await fbSnapshotHistory(rec);
    S.config.lastSnapshot = rec.updatedAt; await saveConfig();
    return true;
  } catch { return false; }
}
/* Po legalnym (administratorskim) usunięciu lub przeniesieniu zgód łańcuch
   integralności trzeba przeliczyć od nowa, żeby „Weryfikuj integralność” był
   zielony. Dowodem sprzed zmiany pozostaje niezmienialna kopia w chmurze. */
async function rebuildChain() {
  const rows = (await getAll("records")).sort((a, b) => (a.seq || 0) - (b.seq || 0));
  let prev = "GENESIS";
  for (const row of rows) {
    const chain = await sha256hex(prev + row.recordHash);
    if (chain !== row.chain) { row.chain = chain; await tx("records", "readwrite", s => s.put(row)); }
    prev = chain;
  }
  S.config.chainHead = prev;
  await saveConfig();
}
/* Przeniesienie zgód do innego projektu — przeszyfrowuje rekord z nowym
   projectId i przelicza jego hash; spójność łańcucha naprawia rebuildChain. */
async function moveRecordsToProject(recs, targetId, targetName) {
  for (const r of recs) {
    const row = await storeGet("records", r.id);
    if (!row) continue;
    const rec = await decryptJSON(S.key, row.pack);
    rec.projectId = targetId; rec.projectName = targetName;
    rec.hash = await sha256hex(JSON.stringify({ ...rec, hash: undefined }));
    row.pack = await encryptJSON(S.key, rec);
    row.recordHash = rec.hash;
    await tx("records", "readwrite", s => s.put(row));
  }
}
/* Czy zgoda ma już kopię w chmurze (była objęta ostatnią udaną synchronizacją). */
function isBackedUp(r) {
  return !!fbCfg() && !!S.config.lastSync && (r.createdAt || "") <= S.config.lastSync;
}
/* Usunięcie zgód — wyłącznie administrator. Najpierw kopia do chmury, potem usunięcie.
   Komunikat mówi: czy powstanie kopia, czy to odwracalne i prosi o potwierdzenie. */
async function deleteRecords(recs) {
  if (!isAdmin() || !recs.length) return;
  const cloud = !!fbCfg();
  const n = recs.length;
  const withCopy = recs.filter(isBackedUp).length, without = n - withCopy;
  const head = n === 1 ? "Usunąć tę zgodę?" : `Usunąć zaznaczone zgody: ${n}?`;
  let msg;
  if (cloud) {
    msg = `${head}\n\nPrzed usunięciem zapiszę kopię w chmurze — usunięcie będzie ODWRACALNE (odzyskasz przez „Przywróć z chmury”).`
      + (without ? `\n\nZ wybranych: ${withCopy} ma już kopię, ${without} jeszcze nie — zapiszę je wszystkie teraz.` : "")
      + `\n\nNa pewno usunąć?`;
  } else {
    msg = `${head}\n\n⚠ Chmura jest wyłączona — kopia NIE powstanie, więc usunięcie będzie NIEODWRACALNE.\n\nNa pewno usunąć?`;
  }
  if (!await uiConfirm(msg)) return;
  if (cloud) { const ok = await snapshotNow(); if (!ok && !await uiConfirm("Nie udało się zapisać kopii w chmurze. Usunąć mimo to — NIEODWRACALNIE?")) return; }
  for (const r of recs) { await tx("records", "readwrite", s => s.delete(r.id)); try { await tx("outbox", "readwrite", s => s.delete(r.id)); } catch {} }
  const ids = new Set(recs.map(r => r.id));
  S.records = S.records.filter(x => !ids.has(x.id));
  await rebuildChain();
  S.selectMode = false; if (S.selected) S.selected.clear();
  scheduleSync();
  enterHome();
}
async function deleteRecord(r) { return deleteRecords([r]); }

/* Usuwanie projektu (admin): najpierw decyzja o zgodach — przenieś do innego/
   nowego projektu albo usuń razem. Zawsze z kopią w chmurze i przebudową łańcucha. */
function openProjectDelete(p) {
  if (!isAdmin()) return;
  const recs = S.records.filter(x => x.projectId === p.id && !x.corrupted);
  const others = (S.vault.projects || []).filter(x => x.id !== p.id);
  const cloud = !!fbCfg();
  const ov = document.createElement("div");
  ov.className = "cam-help";
  const opts = others.map(o => `<option value="${o.id}">${esc(o.name)}</option>`).join("") + `<option value="__new__">➕ Nowy projekt roboczy…</option>`;
  ov.innerHTML = `<div class="cam-help-card rodo-modal-card" style="text-align:left">
    <h3>Usuń projekt „${esc(p.name)}”</h3>
    ${recs.length ? `
      <p class="tiny" style="color:var(--ink-2)">Ten projekt ma <b>${recs.length}</b> ${recs.length === 1 ? "zgodę" : "zgód"}. Projektu nie można usunąć, dopóki są w nim zgody.</p>
      <div class="pd-block">
        <div class="field-label">Przenieś zgody do innego projektu i usuń ten</div>
        <select id="pd-target">${opts}</select>
        <input id="pd-newname" type="text" placeholder="Nazwa nowego projektu roboczego" hidden>
        <button class="btn primary big" id="pd-move">Przenieś zgody i usuń projekt</button>
      </div>
      <div class="pd-note">🛈 Chcesz też usunąć te zgody? Najpierw usuń je na liście („✓ Zaznacz” → 🗑 Usuń), a potem wróć tu i usuń już pusty projekt. To celowe zabezpieczenie przed przypadkowym usunięciem wszystkich zgód.</div>
    ` : `
      <p class="tiny" style="color:var(--ink-2)">Projekt nie ma żadnych zgód.</p>
      <button class="btn danger" id="pd-delempty" style="width:100%">🗑 Usuń projekt</button>
    `}
    <p class="tiny" style="color:var(--muted);margin-top:12px">${cloud ? "Przed usunięciem zapiszę kopię w chmurze — będzie ODWRACALNE (Przywróć z chmury)." : "⚠ Chmura wyłączona — usunięcie będzie NIEODWRACALNE."}</p>
    <div class="cam-help-actions"><button class="btn" id="pd-cancel">Anuluj</button></div>
  </div>`;
  document.body.appendChild(ov);
  const close = () => ov.remove();
  ov.addEventListener("click", e => { if (e.target === ov) close(); });
  ov.querySelector("#pd-cancel").addEventListener("click", close);
  const tgt = ov.querySelector("#pd-target");
  if (tgt) tgt.addEventListener("change", () => { ov.querySelector("#pd-newname").hidden = tgt.value !== "__new__"; });
  async function removeProject() {
    S.vault.projects = S.vault.projects.filter(x => x.id !== p.id);
    if (S.vault.activeProjectId === p.id) S.vault.activeProjectId = (S.vault.projects[0] && S.vault.projects[0].id) || null;
    await saveVault();
  }
  const moveBtn = ov.querySelector("#pd-move");
  if (moveBtn) moveBtn.addEventListener("click", async () => {
    let targetId = tgt.value, targetName;
    if (targetId === "__new__") {
      const nm = ov.querySelector("#pd-newname").value.trim();
      if (!nm) { uiAlert("Podaj nazwę nowego projektu roboczego."); return; }
      targetId = uuid(); targetName = nm;
      S.vault.projects.push({ id: targetId, name: nm, customText: "", files: [], allowedUserIds: [], requirePhoto: false });
    } else { const t = others.find(o => o.id === targetId); targetName = t ? t.name : ""; }
    moveBtn.disabled = true; moveBtn.textContent = "Przenoszę…";
    if (cloud) { const ok = await snapshotNow(); if (!ok && !await uiConfirm("Nie udało się zapisać kopii w chmurze. Kontynuować mimo to?")) { moveBtn.disabled = false; moveBtn.textContent = "Przenieś zgody i usuń projekt"; return; } }
    await moveRecordsToProject(recs, targetId, targetName);
    await removeProject();
    await rebuildChain();
    await loadRecords();
    close(); scheduleSync(); enterSettings();
    uiAlert(`Przeniesiono ${recs.length} ${recs.length === 1 ? "zgodę" : "zgód"} do „${targetName}” i usunięto projekt.`);
  });
  const delEmpty = ov.querySelector("#pd-delempty");
  if (delEmpty) delEmpty.addEventListener("click", async () => {
    if (cloud) await snapshotNow();
    await removeProject();
    close(); scheduleSync(); enterSettings();
  });
}

async function revokeRodo(r) {
  if (!await uiConfirm(`Odnotować cofnięcie zgody RODO przez ${r.person.first} ${r.person.last}?\n\nCofnięcie działa na przyszłość — nie unieważnia zezwolenia art. 81 dla już wyprodukowanego materiału. Dokument pozostaje w archiwum jako dowód.`)) return;
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
    renderAdmins();
    const c = syncCfg();
    $("sync-url").value = c.url || "";
    $("sync-key").value = c.key || "";
    $("sync-auto").checked = c.auto !== false;
    $("sync-autoemail").checked = !!c.autoEmail;
    $("sync-status").textContent = S.config.lastSync ? "Ostatnia synchronizacja: " + new Date(S.config.lastSync).toLocaleString("pl-PL") : "Jeszcze nie synchronizowano.";
    $("restore-list").innerHTML = "";
    const fb = S.vault.fb || {};
    $("fb-enabled").checked = !!fb.enabled;
    $("fb-password").value = fb.password || "";
    $("fb-auto").checked = fb.auto !== false;
    $("fb-email").value = fb.email || FB_DEFAULTS.email;
    $("fb-apikey").value = fb.apiKey || FB_DEFAULTS.apiKey;
    $("fb-projectid").value = fb.projectId || FB_DEFAULTS.projectId;
    $("fb-status").textContent = "";
    $("fb-restore-list").innerHTML = "";
    const m = mailCfg() || {};
    $("mail-email").value = m.email || "hankanobis@offhandfilms.com"; $("mail-pass").value = m.pass || "";
    $("mail-from").value = m.from || ""; $("mail-host").value = m.host || ""; $("mail-port").value = m.port || "";
    $("mail-status").textContent = "";
    renderProjects(); renderLibrary(); renderAccounts(); renderLoginLog(); renderOutbox(); renderStorageInfo();
  }
  show("view-settings");
}
$("btn-settings-back").addEventListener("click", enterHome);

/* --- Rejestr administratorów danych (podmiotów na zgodzie) --- */
function renderAdmins() {
  const box = $("admins-list");
  if (!box) return;
  box.innerHTML = "";
  for (const a of S.vault.admins) {
    const isDef = a.id === S.vault.defaultAdminId;
    const usedBy = S.vault.projects.filter(p => p.adminId === a.id).length;
    const card = document.createElement("div");
    card.className = "admin-card" + (isDef ? " is-default" : "");
    card.innerHTML = `
      <div class="admin-head">
        <span class="admin-badge">${isDef ? "⭐ Domyślny" : "Administrator"}</span>
        <span class="tiny muted">${usedBy ? usedBy + " proj." : ""}</span>
      </div>
      <label>Nazwa / firma<input class="a-name" value="${esc(a.name || "")}" placeholder="np. offhand Hanna Nobis"></label>
      <label>Adres siedziby<input class="a-addr" value="${esc(a.address || "")}" placeholder="ulica, kod, miasto"></label>
      <label>NIP / identyfikator (NIP, CEIDG lub zagraniczny)<input class="a-tax" value="${esc(a.taxId || "")}" placeholder="np. 5213029719"></label>
      <label>E-mail kontaktowy ds. danych (RODO)<input class="a-email" type="email" value="${esc(a.email || "")}" placeholder="np. rodo@offhand.pl"></label>
      <div class="wnav-mini">
        <button class="btn" data-act="save">💾 Zapisz</button>
        ${isDef ? "" : `<button class="btn" data-act="default">⭐ Ustaw domyślnym</button>`}
        ${isDef || S.vault.admins.length < 2 ? "" : `<button class="btn danger" data-act="del">🗑 Usuń</button>`}
      </div>`;
    card.querySelector("[data-act=save]").addEventListener("click", async () => {
      a.name = card.querySelector(".a-name").value.trim() || a.name;
      a.address = card.querySelector(".a-addr").value.trim();
      a.taxId = card.querySelector(".a-tax").value.trim();
      a.email = card.querySelector(".a-email").value.trim();
      normalizeVault(S.vault); await saveVault(); renderAdmins();
    });
    const defBtn = card.querySelector("[data-act=default]");
    if (defBtn) defBtn.addEventListener("click", async () => { S.vault.defaultAdminId = a.id; normalizeVault(S.vault); await saveVault(); renderAdmins(); });
    const delBtn = card.querySelector("[data-act=del]");
    if (delBtn) delBtn.addEventListener("click", async () => {
      if (!await uiConfirm(`Usunąć administratora „${a.name}”? Projekty, które go używały, wrócą do domyślnego.`)) return;
      S.vault.admins = S.vault.admins.filter(x => x.id !== a.id);
      S.vault.projects.forEach(p => { if (p.adminId === a.id) p.adminId = null; });
      normalizeVault(S.vault); await saveVault(); renderAdmins();
    });
    box.appendChild(card);
  }
}
$("btn-add-admin").addEventListener("click", async () => {
  S.vault.admins.push({ id: uuid(), name: "Nowy administrator", address: "", taxId: "", email: "" });
  await saveVault(); renderAdmins();
  const last = $("admins-list").lastElementChild;
  if (last) { last.scrollIntoView({ block: "center" }); const i = last.querySelector(".a-name"); if (i) { i.focus(); i.select(); } }
});

/* --- konfiguracja nadawcy e-mail (administrator) --- */
function smtpFromFields() {
  const email = $("mail-email").value.trim(), pass = $("mail-pass").value;
  if (!email || !pass) return null;
  let host = $("mail-host").value.trim(), port = $("mail-port").value.trim();
  if (!host) { const a = smtpAutodetect(email); if (a) { host = a[0]; if (!port) port = a[1]; } }
  if (!host) return null;
  const from = $("mail-from").value.trim();
  return { host, port: Number(port) || 465, user: email, pass, from: from ? `${from} <${email}>` : email };
}
$("btn-mail-save").addEventListener("click", async () => {
  const st = $("mail-status");
  const email = $("mail-email").value.trim();
  if (email && !isValidEmail(email)) { st.textContent = "⚠ Adres e-mail nadawcy wygląda niepoprawnie."; return; }
  S.vault.mail = { email, pass: $("mail-pass").value, from: $("mail-from").value.trim(), host: $("mail-host").value.trim(), port: $("mail-port").value.trim() };
  if (!S.vault.sync) S.vault.sync = { url: "", key: "", auto: true };
  S.vault.sync.autoEmail = $("sync-autoemail").checked;
  await saveVault();
  if (!email) { st.textContent = "Wyczyszczono dane nadawcy."; return; }
  const auto = smtpAutodetect(email);
  st.textContent = `✅ Zapisano nadawcę: ${email}` + (auto ? ` · serwer wykryty: ${auto[0]}` : ($("mail-host").value.trim() ? "" : " · nieznany dostawca — uzupełnij serwer w ustawieniach zaawansowanych"));
});
$("btn-mail-test").addEventListener("click", async () => {
  const st = $("mail-status");
  const smtp = smtpFromFields();
  if (!smtp) { st.textContent = "🛑 Najpierw wpisz adres e-mail i hasło aplikacji, potem spróbuj ponownie."; return; }
  if (!navigator.onLine) { st.textContent = "🛑 Brak internetu — test wymaga połączenia."; return; }
  const to = (await uiPrompt("Na jaki adres wysłać próbny e-mail?", $("mail-email").value.trim()) || "").trim();
  if (!to) { st.textContent = "Anulowano test."; return; }
  if (!isValidEmail(to)) { st.textContent = "🛑 Ten adres wygląda niepoprawnie: " + to; return; }
  st.textContent = "Wysyłam próbną wiadomość…";
  try {
    const resp = await fetch(FN_EMAIL_URL, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to, subject: "SignOff — test wysyłki", text: "To jest testowa wiadomość z aplikacji SignOff by Offhand. Jeśli ją widzisz — automatyczna wysyłka kopii zgód działa.", smtp }),
    });
    const out = await resp.json().catch(() => ({}));
    st.textContent = resp.ok ? `✅ Wysłano próbny e-mail na ${to}. Sprawdź skrzynkę (zajrzyj też do SPAM-u).` : "🛑 " + (out.error || ("Błąd " + resp.status));
  } catch (e) { st.textContent = "🛑 Błąd połączenia: " + e.message; }
});

/* --- projekty --- */
function renderProjects() {
  const box = $("projects-list");
  box.innerHTML = "";
  if (!S.vault.projects.length) {
    box.innerHTML = `<div class="proj-empty">📁 Brak projektów. Utwórz pierwszy poniżej — po dodaniu rozwiniesz w nim: <b>własną treść zgody</b>, <b>dokumenty PDF do podpisu</b> (z oznaczeniem obowiązkowych), <b>wymóg zdjęcia-dowodu</b> oraz <b>którzy pracownicy</b> mogą w nim zbierać zgody.</div>`;
  }
  const employees = S.config.accounts.filter(a => a.active);
  for (const p of S.vault.projects) {
    p.allowedUserIds = p.allowedUserIds || [];
    const count = S.records.filter(r => !r.corrupted && r.projectId === p.id).length;
    const card = document.createElement("div");
    card.className = "proj-card";
    card.innerHTML = `
      <div class="proj-head"><label class="proj-name-lbl">📁 <input class="proj-name" value="${esc(p.name)}" placeholder="Nazwa projektu"></label><span class="tiny muted">${count} zgód</span></div>
      <label class="tiny">Własna treść zgody (puste = standardowa klauzula wizerunkowa; RODO dołączane zawsze)
        <textarea rows="3" placeholder="np. treść regulaminu wydarzenia…">${esc(p.customText || "")}</textarea>
      </label>
      <label class="tiny">Administrator danych dla tego projektu (na zgodzie / w klauzuli RODO)
        <select class="proj-admin">
          <option value="">⭐ Domyślny (${esc((defaultAdmin() || {}).name || "")})</option>
          ${S.vault.admins.map(a => `<option value="${a.id}" ${p.adminId === a.id ? "selected" : ""}>${esc(a.name)}</option>`).join("")}
          <option value="__new">➕ Dodaj nowego administratora…</option>
        </select>
      </label>
      <div class="proj-allowed"><span class="tiny muted">Uprawnieni (nikt zaznaczony = wszyscy):</span></div>
      <label class="check tiny-check photo-req"><input type="checkbox" ${p.requirePhoto ? "checked" : ""}><span>📷 Zdjęcie-dowód <b>obowiązkowe</b> w tym projekcie</span></label>
      <div class="proj-rec">💡 Rekomendacja: dla bohaterów pierwszoplanowych i wywiadów włącz zdjęcie obowiązkowe — istotnie wzmacnia dowód udzielenia zgody. Dla scen z tłem / przechodniami wystarczy tryb zalecany (domyślny).</div>
      <div class="proj-lib"><span class="tiny muted">Przypięte zgody i dokumenty:</span></div>
      <div class="wnav-mini proj-lib-actions">
        <select class="proj-pin-sel"><option value="">➕ Przypnij istniejącą…</option></select>
        <button class="btn" data-act="newzgoda">＋ Nowa zgoda tu</button>
        <button class="btn" data-act="newdok">＋ Nowy dokument tu</button>
      </div>
      <div class="wnav-mini">
        <button class="btn" data-act="savetext">💾 Zapisz</button>
        <button class="btn danger" data-act="del">🗑 Usuń projekt</button>
      </div>
      <input type="file" class="proj-newfile" accept=".pdf,.docx,application/pdf" hidden>`;
    // zdjęcie obowiązkowe
    card.querySelector(".photo-req input").addEventListener("change", async (e) => {
      p.requirePhoto = e.target.checked;
      await saveVault();
    });
    // administrator danych dla projektu (wybór z listy lub dodanie nowego)
    const adminSel = card.querySelector(".proj-admin");
    adminSel.addEventListener("change", async (e) => {
      if (e.target.value === "__new") {
        const name = (await uiPrompt("Nazwa nowego administratora danych:") || "").trim();
        if (!name) { e.target.value = p.adminId || ""; return; }
        const na = { id: uuid(), name, address: "", taxId: "", email: "" };
        S.vault.admins.push(na); p.adminId = na.id;
        await saveVault(); renderProjects(); renderAdmins();
        uiAlert(`Dodano administratora „${name}". Uzupełnij jego adres / NIP / e-mail w sekcji „Administrator danych" powyżej.`);
        return;
      }
      p.adminId = e.target.value || null;
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
    // przypięte zgody i dokumenty (z biblioteki)
    const libBox = card.querySelector(".proj-lib");
    const pinSel = card.querySelector(".proj-pin-sel");
    const renderProjLib = () => {
      const pinned = projectLibrary(p);
      libBox.innerHTML = `<span class="tiny muted">Przypięte zgody i dokumenty:</span>` + (pinned.length
        ? pinned.map(it => `<div class="attach-row" data-id="${it.id}">
            <div class="attach-info">${it.kind === "zgoda" ? "📝" : "📎"} <b>${esc(it.name || it.fileName || "")}</b>${it.desc ? ` <span class="tiny muted">${esc(it.desc)}</span>` : ""} <span class="tiny muted">${it.type === "pdf" ? (it.pages ? it.pages + " str." : "PDF") : "tekst"}${it.required !== false ? " · ✱ obowiązkowa" : ""}</span></div>
            ${it.type === "pdf" ? `<button class="btn" data-view="${it.id}">👁</button>` : ""}<button class="btn danger" data-unpin="${it.id}">Odepnij</button></div>`).join("")
        : `<p class="tiny muted">Brak — przypnij istniejącą lub dodaj nową poniżej.</p>`);
      libBox.querySelectorAll("[data-view]").forEach(b => b.addEventListener("click", () => openFile(S.vault.library.find(x => x.id === b.dataset.view))));
      libBox.querySelectorAll("[data-unpin]").forEach(b => b.addEventListener("click", async () => {
        const it = S.vault.library.find(x => x.id === b.dataset.unpin); if (!it) return;
        it.projectIds = (it.projectIds || []).filter(x => x !== p.id);
        await saveVault(); renderProjLib(); fillPinSel(); renderLibrary();
      }));
    };
    const fillPinSel = () => {
      const avail = (S.vault.library || []).filter(it => !(it.projectIds || []).includes(p.id));
      pinSel.innerHTML = `<option value="">➕ Przypnij istniejącą…</option>` +
        avail.map(it => `<option value="${it.id}">${it.kind === "zgoda" ? "📝" : "📎"} ${esc(it.name || it.fileName || "")}</option>`).join("");
    };
    renderProjLib(); fillPinSel();
    pinSel.addEventListener("change", async () => {
      const it = S.vault.library.find(x => x.id === pinSel.value); if (!it) return;
      it.projectIds = it.projectIds || []; if (!it.projectIds.includes(p.id)) it.projectIds.push(p.id);
      await saveVault(); renderProjLib(); fillPinSel(); renderLibrary();
    });
    // nowa zgoda/dokument z poziomu projektu
    const newItem = async (kind) => {
      const name = (await uiPrompt(`Nazwa nowej ${kind === "zgoda" ? "zgody" : "dokumentu"}:`) || "").trim();
      if (!name) return;
      const choice = await uiConfirm(`Treść „${name}": wkleić tekst czy wgrać PDF? (Word też zadziała przy „Wgraj PDF".)`, { okLabel: "Wklej tekst", cancelLabel: "Wgraj PDF" });
      if (choice) {
        const text = (await uiPrompt(`Wklej treść „${name}":`, { type: "text" }) || "").trim();
        if (!text) return;
        S.vault.library.push({ id: uuid(), kind, name, desc: "", type: "text", text, required: true, projectIds: [p.id], createdAt: new Date().toISOString() });
        await saveVault(); renderProjLib(); fillPinSel(); renderLibrary();
      } else {
        card.querySelector(".proj-newfile").dataset.kind = kind;
        card.querySelector(".proj-newfile").dataset.name = name;
        card.querySelector(".proj-newfile").click();
      }
    };
    card.querySelector("[data-act=newzgoda]").addEventListener("click", () => newItem("zgoda"));
    card.querySelector("[data-act=newdok]").addEventListener("click", () => newItem("dokument"));
    const newFile = card.querySelector(".proj-newfile");
    newFile.addEventListener("change", async (e) => {
      const f = e.target.files[0]; e.target.value = ""; if (!f) return;
      const kind = newFile.dataset.kind || "dokument", name = newFile.dataset.name || f.name.replace(/\.(pdf|docx)$/i, "");
      try {
        const meta = await addContentFile(f);
        S.vault.library.push({ id: uuid(), kind, name, desc: "", required: true, projectIds: [p.id], createdAt: new Date().toISOString(), ...meta });
        await saveVault(); renderProjLib(); fillPinSel(); renderLibrary();
        if (f.name.toLowerCase().endsWith(".docx")) uiAlert("Word zamieniony na PDF i przypięty. Sprawdź treść (👁).");
      } catch (ex) { uiAlert(ex.message); }
    });
    card.querySelector("[data-act=savetext]").addEventListener("click", async () => {
      const newName = card.querySelector(".proj-name").value.trim();
      if (newName) p.name = newName;
      p.customText = card.querySelector("textarea").value;
      await saveVault();
      uiAlert("Zapisano.");
      renderProjects();
    });
    const del = card.querySelector("[data-act=del]");
    if (del) del.addEventListener("click", () => openProjectDelete(p));
    box.appendChild(card);
  }
}
$("btn-add-project").addEventListener("click", async () => {
  const name = $("new-project-name").value.trim();
  if (!name) { uiAlert("Podaj nazwę projektu."); return; }
  S.vault.projects.push({ id: uuid(), name, customText: "", files: [], allowedUserIds: [], requirePhoto: false });
  $("new-project-name").value = "";
  await saveVault(); renderProjects(); renderLibrary();
});

/* --- biblioteka zgód i dokumentów (wspólna, przypinana do projektów) --- */
function libProjectTags(it) {
  const names = (it.projectIds || []).map(id => (S.vault.projects.find(p => p.id === id) || {}).name).filter(Boolean);
  return names.length ? names.map(n => `<span class="lib-tag">📁 ${esc(n)}</span>`).join("") : `<span class="tiny muted">nieprzypięta</span>`;
}
function renderLibrary() {
  if (!Array.isArray(S.vault.library)) S.vault.library = [];
  for (const kind of ["zgoda", "dokument"]) {
    const box = $("lib-list-" + kind); if (!box) continue;
    box.innerHTML = "";
    const items = S.vault.library.filter(i => i.kind === kind);
    if (!items.length) { box.innerHTML = `<p class="tiny muted">Brak pozycji.</p>`; continue; }
    for (const it of items) box.appendChild(libCard(it));
  }
}
function libCard(it) {
  const card = document.createElement("div");
  card.className = "lib-card";
  const projChecks = (S.vault.projects || []).length
    ? (S.vault.projects).map(p => `<label class="check tiny-check"><input type="checkbox" data-proj="${p.id}" ${(it.projectIds || []).includes(p.id) ? "checked" : ""}><span>${esc(p.name)}</span></label>`).join("")
    : `<span class="tiny muted">Brak projektów — utwórz najpierw projekt.</span>`;
  card.innerHTML = `
    <div class="lib-head"><b>${it.kind === "zgoda" ? "📝" : "📎"} ${esc(it.name || "(bez nazwy)")}</b> <span class="lib-tags">${libProjectTags(it)}</span></div>
    <label class="tiny">Nazwa<input class="lib-c-name" value="${esc(it.name || "")}"></label>
    <label class="tiny">Krótki opis<input class="lib-c-desc" value="${esc(it.desc || "")}" placeholder="opis wyświetlany"></label>
    ${it.type === "text"
      ? `<label class="tiny">Treść<textarea class="lib-c-text" rows="4">${esc(it.text || "")}</textarea></label>`
      : `<div class="attach-row"><div class="attach-info">📄 <b>${esc(it.fileName || "plik.pdf")}</b> <span class="tiny muted">(${((it.size || 0) / 1024).toFixed(0)} KB${it.pages ? ", " + it.pages + " str." : ""})</span></div><button class="btn" data-act="view">👁</button><button class="btn" data-act="replace">↻ Zamień plik</button></div>`}
    <label class="check tiny-check"><input type="checkbox" class="lib-c-req" ${it.required !== false ? "checked" : ""}><span>akceptacja obowiązkowa przy podpisie</span></label>
    <div class="lib-projassign"><span class="tiny muted">Przypięte do projektów:</span>${projChecks}</div>
    <div class="wnav-mini">
      <button class="btn" data-act="save">💾 Zapisz</button>
      <button class="btn" data-act="copy">⧉ Kopiuj</button>
      <button class="btn danger" data-act="del">🗑 Usuń</button>
    </div>
    <input type="file" class="lib-replace-file" accept=".pdf,.docx,application/pdf" hidden>`;
  card.querySelectorAll("[data-proj]").forEach(cb => cb.addEventListener("change", async () => {
    const pid = cb.dataset.proj;
    it.projectIds = it.projectIds || [];
    if (cb.checked) { if (!it.projectIds.includes(pid)) it.projectIds.push(pid); }
    else it.projectIds = it.projectIds.filter(x => x !== pid);
    await saveVault(); card.querySelector(".lib-tags").innerHTML = libProjectTags(it); renderProjects();
  }));
  const reqCb = card.querySelector(".lib-c-req");
  reqCb.addEventListener("change", async () => { it.required = reqCb.checked; await saveVault(); });
  const view = card.querySelector("[data-act=view]"); if (view) view.addEventListener("click", () => openFile(it));
  const replaceBtn = card.querySelector("[data-act=replace]"), replaceInput = card.querySelector(".lib-replace-file");
  if (replaceBtn) replaceBtn.addEventListener("click", () => replaceInput.click());
  replaceInput.addEventListener("change", async (e) => {
    const f = e.target.files[0]; e.target.value = ""; if (!f) return;
    try {
      const meta = await addContentFile(f);
      Object.assign(it, { type: "pdf", fileId: meta.fileId, fileName: meta.fileName, size: meta.size, pages: meta.pages, hash: meta.hash });
      delete it.text;
      await saveVault(); renderLibrary();
      uiAlert(f.name.toLowerCase().endsWith(".docx") ? "Skonwertowano z Worda do PDF — sprawdź treść (👁)." : "Zamieniono plik.");
    } catch (ex) { uiAlert(ex.message); }
  });
  card.querySelector("[data-act=save]").addEventListener("click", async () => {
    it.name = card.querySelector(".lib-c-name").value.trim() || it.name;
    it.desc = card.querySelector(".lib-c-desc").value.trim();
    const ta = card.querySelector(".lib-c-text"); if (ta) it.text = ta.value;
    await saveVault(); renderLibrary(); renderProjects(); uiAlert("Zapisano.");
  });
  card.querySelector("[data-act=copy]").addEventListener("click", async () => {
    const copy = JSON.parse(JSON.stringify(it));
    copy.id = uuid(); copy.name = (it.name || "") + " (kopia)"; copy.projectIds = []; copy.createdAt = new Date().toISOString();
    S.vault.library.push(copy); await saveVault(); renderLibrary();
  });
  card.querySelector("[data-act=del]").addEventListener("click", async () => {
    if (!await uiConfirm(`Usunąć „${it.name}" z biblioteki? Już podpisane zgody zachowują swoją treść i hash.`)) return;
    S.vault.library = S.vault.library.filter(x => x.id !== it.id);
    await saveVault(); renderLibrary(); renderProjects();
  });
  return card;
}
$("btn-lib-addtext").addEventListener("click", async () => {
  const st = $("lib-status");
  const name = $("lib-name").value.trim(), text = $("lib-text").value;
  if (!name) { st.textContent = "🛑 Podaj nazwę."; return; }
  if (!text.trim()) { st.textContent = "🛑 Wpisz treść albo użyj „📎 Wgraj PDF”."; return; }
  S.vault.library.push({ id: uuid(), kind: $("lib-kind").value, name, desc: $("lib-desc").value.trim(), type: "text", text, required: true, projectIds: [], createdAt: new Date().toISOString() });
  await saveVault();
  $("lib-name").value = ""; $("lib-desc").value = ""; $("lib-text").value = "";
  st.textContent = "✅ Dodano. Przypnij do projektów poniżej.";
  renderLibrary();
});
$("btn-lib-addfile").addEventListener("click", () => $("lib-file").click());
$("lib-file").addEventListener("change", async (e) => {
  const f = e.target.files[0]; e.target.value = ""; if (!f) return;
  const st = $("lib-status");
  const name = $("lib-name").value.trim() || f.name.replace(/\.(pdf|docx)$/i, "");
  st.textContent = "Wczytuję plik…";
  try {
    const meta = await addContentFile(f);
    S.vault.library.push({ id: uuid(), kind: $("lib-kind").value, name, desc: $("lib-desc").value.trim(), required: true, projectIds: [], createdAt: new Date().toISOString(), ...meta });
    await saveVault();
    $("lib-name").value = ""; $("lib-desc").value = ""; $("lib-text").value = "";
    st.textContent = f.name.toLowerCase().endsWith(".docx") ? "✅ Word zamieniony na PDF i dodany. Sprawdź treść (👁) i przypnij do projektów." : "✅ Dodano. Przypnij do projektów poniżej.";
    renderLibrary();
  } catch (ex) { st.textContent = "🛑 " + ex.message; }
});

/* --- konta użytkowników (tylko admin) --- */
async function wrapDEKForPin(pin) { return wrapDEKWith(pin); }
function renderAccounts() {
  const box = $("accounts-list");
  box.innerHTML = "";
  for (const acc of S.config.accounts) {
    const row = document.createElement("div");
    row.className = "attach-row";
    row.innerHTML = `
      <div class="attach-info"><b>${esc(acc.name)}</b>
        <span class="tiny muted">${roleLabel(acc.role)}${acc.active ? "" : " · DEZAKTYWOWANE"}${acc.id === S.user.id ? " · (to Ty)" : ""}</span></div>
      <button class="btn" data-act="reset">${acc.id === S.user.id ? "🔑 Zmień mój PIN" : "🔑 Reset PIN"}</button>
      <button class="btn" data-act="rec">🆘 Kod odzyskiwania${acc.recWrap ? "" : " (brak)"}</button>
      ${acc.id !== S.user.id ? `<button class="btn" data-act="toggle">${acc.active ? "⏸ Dezaktywuj" : "▶ Aktywuj"}</button><button class="btn danger" data-act="del">🗑</button>` : ""}
      <div class="reset-box" hidden>
        <input type="password" placeholder="nowy PIN (6+ cyfr)" inputmode="numeric" class="reset-pin">
        <button class="btn primary" data-act="confirm">Zatwierdź</button>
      </div>`;
    row.querySelector("[data-act=reset]").addEventListener("click", () => {
      const rb = row.querySelector(".reset-box"); rb.hidden = !rb.hidden;
    });
    row.querySelector("[data-act=rec]").addEventListener("click", async () => {
      if (acc.recWrap && !await uiConfirm(`Wygenerować NOWY kod odzyskiwania dla „${acc.name}"? Poprzedni kod przestanie działać.`)) return;
      const recCode = genRecoveryCode();
      const rec = await wrapDEKWith(normalizeRecovery(recCode));
      acc.recSalt = rec.salt; acc.recWrap = rec.wrap;
      await saveConfig(); scheduleSync();
      const emailedTo = await emailRecoveryCode(recCode, acc.name);
      await showRecoveryCode(recCode, acc.name, emailedTo);
      renderAccounts();
    });
    row.querySelector("[data-act=confirm]").addEventListener("click", async () => {
      const pin = row.querySelector(".reset-pin").value;
      if (!PIN_RE.test(pin)) { uiAlert("PIN: min. 6 cyfr."); return; }
      const { salt, wrap } = await wrapDEKForPin(pin);
      acc.salt = salt; acc.wrap = wrap; acc.fails = 0; acc.lockUntil = 0;
      await saveConfig(); scheduleSync();
      uiAlert(`Nowy PIN dla „${acc.name}” ustawiony.`);
      renderAccounts();
    });
    const tg = row.querySelector("[data-act=toggle]");
    if (tg) tg.addEventListener("click", async () => {
      if (acc.role === "admin" && acc.active && S.config.accounts.filter(a => a.active && a.role === "admin").length <= 1) { uiAlert("Musi pozostać co najmniej jeden aktywny administrator."); return; }
      acc.active = !acc.active;
      await saveConfig(); scheduleSync(); renderAccounts();
    });
    const dl = row.querySelector("[data-act=del]");
    if (dl) dl.addEventListener("click", async () => {
      if (acc.role === "admin" && S.config.accounts.filter(a => a.active && a.role === "admin").length <= 1) { uiAlert("Musi pozostać co najmniej jeden aktywny administrator."); return; }
      if (!await uiConfirm(`Usunąć konto „${acc.name}”? Zebrane przez nie zgody pozostają w archiwum.`)) return;
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
  const recCode = genRecoveryCode();
  const rec = await wrapDEKWith(normalizeRecovery(recCode));
  S.config.accounts.push({ id: uuid(), name, role, salt, wrap, recSalt: rec.salt, recWrap: rec.wrap, fails: 0, lockUntil: 0, active: true, createdAt: new Date().toISOString() });
  await saveConfig(); scheduleSync();
  $("new-acc-name").value = ""; $("new-acc-pin").value = ""; $("new-acc-pin2").value = "";
  renderAccounts();
  const emailedTo = await emailRecoveryCode(recCode, name);
  await showRecoveryCode(recCode, name, emailedTo);
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
  uiAlert("Twój PIN został zmieniony.");
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
  text("[X] Zezwolenie na rozpowszechnianie wizerunku, głosu i wypowiedzi oraz przeniesienie praw (art. 81 pr. aut.) — UDZIELONE", { size: 9.5 });
  text("[X] Zgoda na przetwarzanie danych osobowych (art. 6 ust. 1 lit. a RODO) — UDZIELONA", { size: 9.5 });
  text(`[${r.consents.marketing ? "X" : "  "}] Zgoda dodatkowa (informacje o przyszłych projektach i oferty współpracy) — ${r.consents.marketing ? "UDZIELONA" : "NIEUDZIELONA"}`, { size: 9.5, gap: 6 });
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

/* ===================== Regulamin i klauzula RODO dla użytkowników aplikacji ===================== */
const RODO_USERS_TEXT =
`REGULAMIN KORZYSTANIA Z APLIKACJI SignOff by Offhand

1. Aplikacja służy wyłącznie do zbierania zgód (wizerunek, RODO) i podpisywania dokumentów w imieniu administratora — Offhand Hanna Nobis.
2. Każdy użytkownik (administrator, pracownik, inne) loguje się własnym PIN-em i odpowiada za jego poufność. PIN-u nie wolno udostępniać.
3. Dane są szyfrowane na urządzeniu (AES-256). Aplikacja działa offline; kopia w chmurze, jeśli włączona, przechowuje wyłącznie zaszyfrowane dane.
4. Użytkownik zbiera zgody tylko w przydzielonych projektach i zgodnie z poleceniem administratora.
5. Zabronione jest modyfikowanie, kopiowanie lub usuwanie zebranych zgód poza aplikacją — integralność jest weryfikowana kryptograficznie.

KLAUZULA INFORMACYJNA (RODO) DLA UŻYTKOWNIKÓW APLIKACJI

1. Administratorem danych osobowych użytkowników jest Offhand Hanna Nobis.
2. Zakres danych użytkownika: imię i nazwisko, rola, identyfikator urządzenia oraz informacja, kto i kiedy zebrał daną zgodę (rozliczalność). PIN nie jest przechowywany w postaci jawnej — służy wyłącznie do odszyfrowania danych na urządzeniu.
3. Cel i podstawa: organizacja i rozliczalność procesu zbierania zgód — art. 6 ust. 1 lit. b oraz lit. f RODO (prawnie uzasadniony interes administratora: bezpieczeństwo i wykazanie, kto zebrał zgodę).
4. Dane przechowywane są przez okres korzystania z aplikacji oraz okres przedawnienia roszczeń; kopie w chmurze są zaszyfrowane end-to-end.
5. Przysługuje prawo dostępu do danych, sprostowania, usunięcia, ograniczenia, sprzeciwu oraz skargi do Prezesa UODO.
6. Dane nie są wykorzystywane do profilowania ani automatycznego podejmowania decyzji.

Kontakt w sprawie danych: Offhand Hanna Nobis.`;
const APP_URL = "https://signoffbyoffhand.github.io/";
{
  const ic = $("btn-install-copy");
  if (ic) ic.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(APP_URL); ic.textContent = "✅ Skopiowano"; setTimeout(() => ic.textContent = "📋 Kopiuj link", 2000); }
    catch { ic.textContent = "Skopiuj ręcznie: " + APP_URL; }
  });
}
$("link-rodo").addEventListener("click", (e) => { e.preventDefault(); $("rodo-doc").textContent = RODO_USERS_TEXT; $("rodo-modal").hidden = false; });
$("btn-rodo-close").addEventListener("click", () => { $("rodo-modal").hidden = true; });
$("link-reset").addEventListener("click", (e) => {
  e.preventDefault();
  $("rec-code").value = ""; $("rec-pin").value = "";
  $("rec-status").textContent = "";
  $("reset-modal").hidden = false;
});
$("btn-reset-close").addEventListener("click", () => { $("reset-modal").hidden = true; });
$("btn-rec-go").addEventListener("click", async () => {
  const st = $("rec-status");
  const code = $("rec-code").value, pin = $("rec-pin").value;
  if (normalizeRecovery(code).length < 12) { st.textContent = "🛑 Wpisz pełny kod odzyskiwania."; return; }
  if (!PIN_RE.test(pin)) { st.textContent = "🛑 Nowy PIN musi mieć co najmniej 6 cyfr."; return; }
  st.textContent = "Sprawdzam kod…";
  const acc = await recoverWithCode(code, pin);
  if (acc) { $("reset-modal").hidden = true; enterHome(); }
  else st.textContent = "🛑 Nieprawidłowy kod odzyskiwania (albo to konto nie ma jeszcze kodu).";
});

boot();

/* ===== Dekoracja: licznik kroków kreatora "n/5" + procent paska postępu =====
   Czysto wizualne, addytywne. Obserwuje #wizard-steps (renderowany w gotoStep)
   i aktualizuje licznik oraz zmienną CSS --wizard-pct dla ciągłego paska. */
(function () {
  const stepsEl = document.getElementById("wizard-steps");
  const countEl = document.getElementById("wizard-step-count");
  if (!stepsEl) return;
  const sync = () => {
    const dots = stepsEl.querySelectorAll(".step-dot");
    const total = dots.length || 5;
    let cur = 1;
    dots.forEach((d, i) => { if (d.classList.contains("active")) cur = i + 1; });
    if (countEl) countEl.textContent = cur + "/" + total;
    stepsEl.style.setProperty("--wizard-pct", Math.round((cur / total) * 100) + "%");
  };
  new MutationObserver(sync).observe(stepsEl, { childList: true });
  sync();
})();

/* ===== Dekoracja: karta dowodowa na ekranie „Zgoda zapisana" =====
   Czysto wizualna. Obserwuje #done-info (tekst ustawiany przez logikę zapisu,
   format: „ID: <id> · SHA-256: <hash>… · …") i wyciąga ID oraz skrót do karty
   dowodowej zgodnej z wzorcem. Nie zmienia logiki — tylko prezentuje. */
(function () {
  const info = document.getElementById("done-info");
  const card = document.getElementById("evidence-card");
  if (!info || !card) return;
  const idEl = document.getElementById("evidence-id");
  const hashEl = document.getElementById("evidence-hash");
  const sync = () => {
    const t = info.textContent || "";
    const idM = t.match(/ID:\s*([^\s·]+)/);
    const shM = t.match(/SHA-256:\s*([0-9a-fA-F]+)/);
    if (idM && shM) {
      if (idEl) idEl.textContent = idM[1];
      if (hashEl) hashEl.textContent = shM[1];
      card.hidden = false;
    } else {
      card.hidden = true;
    }
  };
  new MutationObserver(sync).observe(info, { childList: true, characterData: true, subtree: true });
  sync();
})();

/* Awatary statusu na liście zgód renderuje teraz bezpośrednio renderList
   (wraz z plakietkami, ikonami akcji i trybem zaznaczania) — osobny
   obserwator nie jest już potrzebny. */
