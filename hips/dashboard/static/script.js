const POLL_INTERVAL_MS = 2500;

const el = {
  clock: document.getElementById("clock"),
  hostIp: document.getElementById("host-ip"),
  statTotal: document.getElementById("stat-total"),
  statHigh: document.getElementById("stat-high"),
  statMedium: document.getElementById("stat-medium"),
  statLow: document.getElementById("stat-low"),
  typeList: document.getElementById("type-list"),
  logFeed: document.getElementById("log-feed"),
  emptyState: document.getElementById("empty-state"),
  pulseStrip: document.getElementById("pulse-strip"),
  liveDot: document.getElementById("live-dot"),
  errorBanner: document.getElementById("error-banner"),
};

el.hostIp.textContent = window.location.hostname || "localhost";

let lastNewestKey = null;
const expandedKeys = new Set();

function tickClock() {
  const now = new Date();
  el.clock.textContent = now.toTimeString().slice(0, 8);
}
tickClock();
setInterval(tickClock, 1000);

function alertKey(a) {
  return `${a.timestamp || ""}|${a.type || ""}|${JSON.stringify(a.details || {})}`;
}

function severityLabel(sev) {
  if (sev === "high") return "haute";
  if (sev === "medium") return "moy.";
  if (sev === "low") return "basse";
  return sev || "?";
}

function formatDetails(a) {
  const d = a.details || {};
  const parts = [];
  for (const [k, v] of Object.entries(d)) {
    parts.push(`<b>${k}</b>=${v}`);
  }
  return parts.join("  ");
}

function flashPulse() {
  el.pulseStrip.classList.add("alert-flash");
  setTimeout(() => el.pulseStrip.classList.remove("alert-flash"), 900);
}

function render(data) {
  const { alerts, stats, by_type } = data;

  el.statTotal.textContent = stats.total;
  el.statHigh.textContent = stats.high;
  el.statMedium.textContent = stats.medium;
  el.statLow.textContent = stats.low;

  // Répartition par type
  el.typeList.innerHTML = "";
  const maxCount = Math.max(1, ...Object.values(by_type));
  const sortedTypes = Object.entries(by_type).sort((a, b) => b[1] - a[1]);

  if (sortedTypes.length === 0) {
    el.typeList.innerHTML = `<div class="type-row" style="color: var(--text-dim)">aucune donnée</div>`;
  } else {
    for (const [type, count] of sortedTypes) {
      const row = document.createElement("div");
      row.className = "type-row";
      row.innerHTML = `
        <span>${type}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(count / maxCount) * 100}%"></span></span>
        <span class="count">${count}</span>
      `;
      el.typeList.appendChild(row);
    }
  }

  // Flux d'alertes
  if (alerts.length === 0) {
    el.logFeed.innerHTML = "";
    el.logFeed.appendChild(el.emptyState);
    lastNewestKey = null;
    return;
  }

  const newestKey = alertKey(alerts[0]);
  if (lastNewestKey !== null && newestKey !== lastNewestKey) {
    flashPulse();
  }
  lastNewestKey = newestKey;

  el.logFeed.innerHTML = "";
  for (const a of alerts) {
    const row = document.createElement("div");
    const sev = a.severity || "low";
    const key = alertKey(a);
    row.className = `log-row sev-${sev}` + (expandedKeys.has(key) ? " expanded" : "");
    const time = (a.timestamp || "").slice(11, 19) || "--:--:--";
    row.innerHTML = `
      <span class="time">${time}</span>
      <span class="sev">${severityLabel(sev)}</span>
      <span class="type">${a.type || "inconnu"}</span>
      <span class="details">${formatDetails(a)}</span>
    `;
    row.addEventListener("click", () => {
      row.classList.toggle("expanded");
      if (expandedKeys.has(key)) {
        expandedKeys.delete(key);
      } else {
        expandedKeys.add(key);
      }
    });
    el.logFeed.appendChild(row);
  }
}

async function poll() {
  try {
    const res = await fetch("/api/alerts", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    render(data);
    el.errorBanner.classList.remove("show");
    el.liveDot.textContent = "en écoute";
  } catch (err) {
    el.errorBanner.classList.add("show");
    el.liveDot.textContent = "hors ligne";
  }
}

poll();
setInterval(poll, POLL_INTERVAL_MS);
