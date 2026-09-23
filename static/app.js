const tbody = document.getElementById("serviceRows");
const errorBox = document.getElementById("errorBox");
const refreshBtn = document.getElementById("refreshBtn");
const searchInput = document.getElementById("searchInput");
const serviceCount = document.getElementById("serviceCount");
const protectedSet = new Set(window.PROTECTED_SERVICES || []);

const navItems = document.querySelectorAll(".nav-item[data-view]");
const views = document.querySelectorAll(".view");

const lsHealthBadge = document.getElementById("lsHealthBadge");
const lsRefreshBtn = document.getElementById("lsRefreshBtn");
const lsAutoRefresh = document.getElementById("lsAutoRefresh");
const lsStatCards = document.getElementById("lsStatCards");
const lsPipelineRows = document.getElementById("lsPipelineRows");
const lsErrorsBox = document.getElementById("lsErrorsBox");

const lsEsErrorsRefreshBtn = document.getElementById("lsEsErrorsRefreshBtn");
const lsEsErrorsAutoRefresh = document.getElementById("lsEsErrorsAutoRefresh");
const lsEsErrorsPathInput = document.getElementById("lsEsErrorsPathInput");
const lsEsErrorsLoadBtn = document.getElementById("lsEsErrorsLoadBtn");
const lsEsErrorRows = document.getElementById("lsEsErrorRows");
const lsEsErrorSample = document.getElementById("lsEsErrorSample");
const lsLogPathInput = document.getElementById("lsLogPathInput");
const lsGrepInput = document.getElementById("lsGrepInput");
const lsLogLinesSelect = document.getElementById("lsLogLinesSelect");
const lsLoadLogBtn = document.getElementById("lsLoadLogBtn");
const lsAutoRefreshLog = document.getElementById("lsAutoRefreshLog");
const lsLogOutput = document.getElementById("lsLogOutput");
const lsChips = document.querySelectorAll("#lsGrepQuickFilters .chip");
const lsLogDateStart = document.getElementById("lsLogDateStart");
const lsLogDateEnd = document.getElementById("lsLogDateEnd");
const lsLogDateClearBtn = document.getElementById("lsLogDateClearBtn");
const lsLogDateActiveNote = document.getElementById("lsLogDateActiveNote");

const lsHistoryPipeline = document.getElementById("lsHistoryPipeline");
const lsPipelineOptions = document.getElementById("lsPipelineOptions");
const lsHistoryStart = document.getElementById("lsHistoryStart");
const lsHistoryEnd = document.getElementById("lsHistoryEnd");
const lsHistoryLoadBtn = document.getElementById("lsHistoryLoadBtn");
const lsHistoryClearBtn = document.getElementById("lsHistoryClearBtn");
const lsHistoryChips = document.querySelectorAll("#lsHistoryQuickRanges .chip[data-minutes]");
const lsFilterActiveNote = document.getElementById("lsFilterActiveNote");

const historyRows = document.getElementById("historyRows");
const historyRefreshBtn = document.getElementById("historyRefreshBtn");
const historyServiceFilter = document.getElementById("historyServiceFilter");
const historyServiceOptions = document.getElementById("historyServiceOptions");
const historyStart = document.getElementById("historyStart");
const historyEnd = document.getElementById("historyEnd");
const historyLoadBtn = document.getElementById("historyLoadBtn");
const historyChips = document.querySelectorAll("#historyQuickRanges .chip[data-minutes]");
const historyFilterActiveNote = document.getElementById("historyFilterActiveNote");

let lsStatsTimer = null;
let lsLogTimer = null;
let lsEsErrorsTimer = null;
let lsStatsLoadedOnce = false;
let lsEsErrorsLoadedOnce = false;
let historyLoadedOnce = false;
let lsPrevReadings = {}; // pipeline id -> { out, ts } for client-side evt/s
let lsLogRawContent = ""; // last-fetched raw log text, re-filtered client-side by date without a re-fetch
let lsStatusFilter = null; // null | "up" | "issues" | "down" -- set by clicking a stat card, applies to the live pipeline table
let lsLastStatsData = null; // last full /logstash/stats response, kept so toggling the status filter re-renders without a re-fetch
const API_BASE = `/api/servers/${window.SERVER_ID}`;

const ICON_PLAY =
  '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="6 3 20 12 6 21 6 3"></polygon></svg>';
const ICON_STOP =
  '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="14" rx="1"></rect></svg>';
const ICON_RESTART =
  '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>';
const ICON_INFO =
  '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : str;
  return div.innerHTML;
}

// Full control grants every service; otherwise only the ones an admin listed
// individually (window.CONTROLLABLE_SERVICES) show Start/Stop. The server enforces
// this too -- this only decides which buttons are worth showing.
function canControlService(name) {
  if (window.CAN_CONTROL) return true;
  return Array.isArray(window.CONTROLLABLE_SERVICES) && window.CONTROLLABLE_SERVICES.includes(name);
}

let allServices = [];

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("d-none");
  errorBox.scrollIntoView({ behavior: "smooth", block: "center" });
}

function clearError() {
  errorBox.classList.add("d-none");
  errorBox.textContent = "";
}

function statusBadgeClass(active) {
  if (active === "active") return "status-running";
  if (active === "failed") return "status-failed";
  return "status-stopped";
}

function renderRow(service) {
  const tr = document.createElement("tr");
  tr.dataset.name = service.name;

  const isProtected = protectedSet.has(service.name);
  const nameCell = document.createElement("td");
  nameCell.textContent = service.name;
  nameCell.className = "service-name";
  if (isProtected) nameCell.classList.add("protected-name");

  const statusCell = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = `status-badge ${statusBadgeClass(service.active)}`;
  badge.textContent = service.active;
  statusCell.appendChild(badge);

  const descCell = document.createElement("td");
  descCell.textContent = service.description || "";
  descCell.style.color = "var(--color-muted)";

  const actionsCell = document.createElement("td");
  actionsCell.className = "text-end service-actions";

  const detailsBtn = document.createElement("button");
  detailsBtn.className = "btn-icon";
  detailsBtn.innerHTML = ICON_INFO;
  detailsBtn.title = "Show restart policy / what could relaunch this service";
  detailsBtn.onclick = () => toggleDetails(service.name, tr);

  actionsCell.appendChild(detailsBtn);

  if (canControlService(service.name)) {
    const startBtn = document.createElement("button");
    startBtn.className = "btn-action btn-start";
    startBtn.innerHTML = `${ICON_PLAY} Start`;
    startBtn.disabled = service.active === "active";
    startBtn.onclick = () => performAction(service.name, "start", isProtected);

    const stopBtn = document.createElement("button");
    stopBtn.className = "btn-action btn-stop";
    stopBtn.innerHTML = `${ICON_STOP} Stop`;
    stopBtn.disabled = service.active !== "active";
    stopBtn.onclick = () => performAction(service.name, "stop", isProtected);

    // Restart works regardless of current state (systemctl restart on an
    // already-stopped unit just starts it), so it's never disabled -- unlike
    // Start/Stop, which only make sense in one direction at a time.
    const restartBtn = document.createElement("button");
    restartBtn.className = "btn-action btn-restart";
    restartBtn.innerHTML = `${ICON_RESTART} Restart`;
    restartBtn.title = "Stop then start this service in one step";
    restartBtn.onclick = () => performAction(service.name, "restart", isProtected);

    actionsCell.append(startBtn, stopBtn, restartBtn);
  }

  tr.append(nameCell, statusCell, descCell, actionsCell);
  return tr;
}

function renderDetailsHtml(d) {
  const restart = d.Restart || "no";
  const triggeredBy = d.TriggeredBy || "";
  const partOf = d.PartOf || "";
  const wantedBy = d.WantedBy || "";
  const requiredBy = d.RequiredBy || "";
  const fragmentPath = d.FragmentPath || "";

  let warnings = "";
  if (triggeredBy) {
    warnings += `<div class="detail-warning">Triggered by <strong>${escapeHtml(triggeredBy)}</strong> &mdash; if that's a .socket/.path/.timer unit, it can relaunch this service shortly after a manual Stop (e.g. socket activation). Stop that unit too if you need this to stay down.</div>`;
  }
  if (restart && restart !== "no") {
    warnings += `<div class="detail-warning">Restart policy is <strong>${escapeHtml(restart)}</strong> &mdash; systemd auto-restarts this on an unexpected exit (a manual Stop is not affected by this).</div>`;
  }
  if (!warnings) {
    warnings = `<div class="detail-warning detail-info">No socket/path/timer trigger and no auto-restart policy found. If it comes back after Stop, something outside systemd (a cron job, script, or supervisor) is likely restarting it.</div>`;
  }

  const rows = [
    ["Restart policy", restart],
    ["Triggered by", triggeredBy],
    ["Part of", partOf],
    ["Wanted by", wantedBy],
    ["Required by", requiredBy],
    ["Unit file", fragmentPath],
  ];

  const grid = rows
    .map(([label, value]) => `<div><span>${label}</span><strong>${escapeHtml(value) || "&mdash;"}</strong></div>`)
    .join("");

  return `<div class="details-panel">${warnings}<div class="details-grid">${grid}</div></div>`;
}

async function toggleDetails(name, tr) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains("details-row")) {
    existing.remove();
    if (existing.dataset.for === name) return;
  }

  clearError();
  try {
    const res = await fetch(`${API_BASE}/services/${encodeURIComponent(name)}/details`);
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to load details");

    const detailsRow = document.createElement("tr");
    detailsRow.className = "details-row";
    detailsRow.dataset.for = name;
    const td = document.createElement("td");
    td.colSpan = 4;
    td.innerHTML = renderDetailsHtml(data);
    detailsRow.appendChild(td);
    tr.after(detailsRow);
  } catch (err) {
    showError(err.message);
  }
}

function renderServices(services) {
  tbody.innerHTML = "";
  serviceCount.textContent = `${services.length} of ${allServices.length}`;
  if (services.length === 0) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No services found.</td></tr>';
    return;
  }
  services.forEach((service) => tbody.appendChild(renderRow(service)));
}

function applySearchFilter() {
  const query = searchInput.value.trim().toLowerCase();
  const filtered = query
    ? allServices.filter((s) => s.name.toLowerCase().includes(query))
    : allServices;
  renderServices(filtered);
}

// ============================================================
// Start/Stop History -- server-backed audit log (see db.record_service_action
// / /api/servers/<id>/services/history). Every start/stop performed through
// this dashboard is recorded there, so this survives page reloads and is
// shared across whoever views this server -- unlike the old per-browser,
// session-only localStorage list this replaces.
// ============================================================

function renderServiceHistoryOptions(names) {
  historyServiceOptions.innerHTML = names.map((n) => `<option value="${escapeHtml(n)}"></option>`).join("");
}

function renderServiceHistoryRows(entries) {
  historyRows.innerHTML = "";
  if (!entries.length) {
    historyRows.innerHTML = '<tr class="empty-row"><td colspan="5">No start/stop/restart actions recorded in this range.</td></tr>';
    return;
  }

  entries.forEach((entry) => {
    const tr = document.createElement("tr");

    const timeCell = document.createElement("td");
    timeCell.style.color = "var(--color-muted)";
    timeCell.textContent = new Date(entry.performed_at * 1000).toLocaleString();

    const nameCell = document.createElement("td");
    nameCell.textContent = entry.service_name;

    const actionCell = document.createElement("td");
    actionCell.textContent = { start: "Start", stop: "Stop", restart: "Restart" }[entry.action] || entry.action;

    const resultCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `result-badge ${entry.success ? "result-success" : "result-failed"}`;
    badge.textContent = entry.success ? "Success" : "Failed";
    resultCell.appendChild(badge);
    if (!entry.success && entry.message) {
      const detail = document.createElement("span");
      detail.style.color = "var(--color-muted)";
      detail.style.marginLeft = "0.5rem";
      detail.style.fontSize = "0.78rem";
      detail.textContent = entry.message;
      resultCell.appendChild(detail);
    }

    const byCell = document.createElement("td");
    byCell.style.color = "var(--color-muted)";
    byCell.textContent = entry.performed_by_username || "unknown";

    tr.append(timeCell, nameCell, actionCell, resultCell, byCell);
    historyRows.appendChild(tr);
  });
}

async function loadServiceHistory(quickMinutes, chipEl) {
  const params = new URLSearchParams();
  const service = historyServiceFilter.value.trim();
  if (service) params.set("service", service);

  let rangeLabel;
  if (quickMinutes) {
    params.set("minutes", quickMinutes);
    historyStart.value = "";
    historyEnd.value = "";
    rangeLabel = chipEl ? chipEl.textContent : `last ${quickMinutes} min`;
  } else {
    if (historyStart.value) params.set("start", historyStart.value);
    if (historyEnd.value) params.set("end", historyEnd.value);
    rangeLabel = historyStart.value || historyEnd.value ? "custom range" : null;
  }
  setActiveChip(historyChips, chipEl || null);
  updateFilterNote(historyFilterActiveNote, [rangeLabel, service ? `service: "${service}"` : null]);

  historyRows.innerHTML = '<tr class="empty-row"><td colspan="5">Loading&hellip;</td></tr>';
  try {
    const res = await fetch(`${API_BASE}/services/history?${params.toString()}`);
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to load history");
    renderServiceHistoryOptions(data.service_names || []);
    renderServiceHistoryRows(data.entries || []);
  } catch (err) {
    historyRows.innerHTML = `<tr class="empty-row"><td colspan="5">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function loadServices() {
  clearError();
  try {
    const res = await fetch(`${API_BASE}/services`);
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to load services");
    allServices = data.services;
    applySearchFilter();
  } catch (err) {
    showError(err.message);
  }
}

async function performAction(name, action, isProtected) {
  if (isProtected) {
    const confirmed = window.confirm(
      `${name} is a system-critical service. Are you sure you want to ${action} it?`
    );
    if (!confirmed) return;
  }

  clearError();
  try {
    const res = await fetch(`${API_BASE}/services/${encodeURIComponent(name)}/${action}`, {
      method: "POST",
    });
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Failed to ${action} ${name}`);
    await loadServices();
  } catch (err) {
    showError(err.message);
  } finally {
    // Refresh from the server-backed audit log either way -- it's the source of
    // truth now (see db.record_service_action), not a local optimistic copy.
    // Re-use whatever quick-range is currently active instead of resetting it.
    // Also marks History as already-loaded so visiting that page next doesn't
    // trigger a redundant duplicate fetch on top of this one.
    historyLoadedOnce = true;
    const activeChip = document.querySelector("#historyQuickRanges .chip.active");
    if (activeChip) loadServiceHistory(activeChip.dataset.minutes, activeChip);
    else loadServiceHistory();
  }
}

// ============================================================
// Logstash view: pipeline status, in/out metrics, grep filter
// ============================================================

function lsHealthClass(status) {
  if (status === "green") return "status-running";
  if (status === "red") return "status-failed";
  return "status-stopped"; // yellow / unknown -- no dedicated warning badge yet
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

// Pipeline IDs a hover-preview title lists before switching to "+N more" --
// keeps the native browser tooltip from becoming an unreadable wall of text
// when hundreds of pipelines share a status (mainly "Up").
const STATUS_PREVIEW_LIMIT = 20;

function pipelineIdsByHealth(pipelines, health) {
  return Object.keys(pipelines || {}).filter((id) => pipelines[id].health === health);
}

function statusHoverTitle(ids) {
  if (!ids.length) return "";
  const shown = ids.slice(0, STATUS_PREVIEW_LIMIT).join("\n");
  const remaining = ids.length - STATUS_PREVIEW_LIMIT;
  return remaining > 0 ? `${shown}\n+${remaining} more` : shown;
}

function renderLsStatCards(data) {
  if (!lsStatCards) return; // Pipeline Status page not granted -- nothing to render into.
  const pipelines = data.pipelines || {};
  const cards = [
    ["Server", window.SERVER_HOST || data.name || "—", "", "", null],
    ["Logstash Uptime", data.uptime_seconds != null ? formatUptime(data.uptime_seconds) : "—", "", "", null],
    ["Pipelines", Object.keys(pipelines).length, "hero", "", null],
    ["Up", data.pipeline_up_count ?? 0, "success", "Running, no reload failures", "up"],
    ["Issues", data.pipeline_issues_count ?? 0, "warning", "Running, but had a reload failure", "issues"],
    ["Down", data.pipeline_down_count ?? 0, "danger", "Loaded but not processing (0 workers)", "down"],
  ];
  lsStatCards.innerHTML = cards
    .map(([label, value, variant, desc, status]) => {
      const cls = variant ? ` stat-card--${variant}` : "";
      const selectedCls = status && lsStatusFilter === status ? " stat-card--selected" : "";
      const descHtml = desc ? `<span class="stat-desc">${escapeHtml(desc)}</span>` : "";
      const statusAttr = status ? ` data-status="${status}"` : "";
      // Hover preview: which pipelines are actually in this state, without
      // having to click first. Native title tooltip -- no extra JS needed.
      const title = status ? escapeHtml(statusHoverTitle(pipelineIdsByHealth(pipelines, status))) : "";
      const titleAttr = title ? ` title="${title}"` : "";
      return `<div class="stat-card${cls}${selectedCls}"${statusAttr}${titleAttr}><span class="stat-label">${escapeHtml(label)}</span><span class="stat-value">${escapeHtml(String(value))}</span>${descHtml}</div>`;
    })
    .join("");
}

const LS_HEALTH_BADGE = {
  up: { label: "UP", cls: "status-running" },
  issues: { label: "ISSUES", cls: "status-warning" },
  down: { label: "DOWN", cls: "status-failed" },
};

function lsPipelineHealthBadge(health) {
  const info = LS_HEALTH_BADGE[health] || { label: "UNKNOWN", cls: "status-stopped" };
  return `<span class="status-badge ${info.cls}">${info.label}</span>`;
}

function renderLsPipelines(pipelines) {
  // Pipeline Status and Reload/Config Errors are independently grantable pages
  // that both render from this one fetch (see loadLsStats) -- a user might
  // have only one of the two, so lsPipelineRows (Status) and lsErrorsBox
  // (Errors) are guarded independently throughout, never assumed present together.
  const filter = lsHistoryPipeline ? lsHistoryPipeline.value.trim().toLowerCase() : "";
  const ids = Object.keys(pipelines || {}).filter((id) => {
    if (filter && !id.toLowerCase().includes(filter)) return false;
    if (lsStatusFilter && pipelines[id].health !== lsStatusFilter) return false;
    return true;
  });
  if (lsPipelineRows) lsPipelineRows.innerHTML = "";

  if (ids.length === 0) {
    const emptyMessage = lsStatusFilter
      ? `No pipelines with status "${lsStatusFilter}" right now.`
      : "No pipelines reported.";
    if (lsPipelineRows) lsPipelineRows.innerHTML = `<tr class="empty-row"><td colspan="10">${escapeHtml(emptyMessage)}</td></tr>`;
    if (lsErrorsBox) lsErrorsBox.textContent = "No reload/config errors detected.";
    return;
  }

  const now = Date.now();
  const nowLabel = formatSnapshotTime(now / 1000);
  const errorMessages = [];

  ids.forEach((id) => {
    const p = pipelines[id];
    const prev = lsPrevReadings[id];
    let rate = "—";
    if (prev) {
      const dt = (now - prev.ts) / 1000;
      if (dt > 0.5) rate = ((p.events_out - prev.out) / dt).toFixed(1);
    }
    lsPrevReadings[id] = { out: p.events_out, ts: now };

    if (lsPipelineRows) {
      const tr = document.createElement("tr");

      const timeTd = document.createElement("td");
      timeTd.textContent = nowLabel;
      tr.appendChild(timeTd);

      const nameTd = document.createElement("td");
      nameTd.textContent = id;
      tr.appendChild(nameTd);

      const statusTd = document.createElement("td");
      statusTd.innerHTML = lsPipelineHealthBadge(p.health);
      tr.appendChild(statusTd);

      [
        p.workers,
        p.events_in,
        p.events_filtered,
        p.events_out,
        rate,
        `${p.queue_type} (${p.queue_events ?? 0})`,
        p.reload_failures || 0,
      ].forEach((val, idx) => {
        const td = document.createElement("td");
        td.textContent = val;
        if (idx === 6 && Number(val) > 0) td.style.color = "var(--color-danger)";
        tr.appendChild(td);
      });
      lsPipelineRows.appendChild(tr);
    }

    if (p.reload_failures > 0) {
      const detail = p.reload_last_error && p.reload_last_error.message ? p.reload_last_error.message : "see Logstash log for details";
      errorMessages.push(`[${id}] ${p.reload_failures} failed reload(s) -- last error: ${detail}`);
    }
  });

  if (lsErrorsBox) {
    lsErrorsBox.textContent = errorMessages.length ? errorMessages.join("\n") : "No reload/config errors detected.";
  }
}

const LS_API_PORT = "9600"; // Logstash Monitoring API port -- fixed, no longer user-editable in the UI

async function loadLsStats() {
  clearError();
  try {
    const res = await fetch(`${API_BASE}/logstash/stats?port=${encodeURIComponent(LS_API_PORT)}`);
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to load Logstash stats");
    lsLastStatsData = data; // so clicking a stat card can re-filter without a re-fetch

    // lsHealthBadge lives on the Pipeline Status page only -- null for a user
    // who has just Reload/Config Errors (see renderLsPipelines' comment above
    // for why the rest of this function stays common to both pages).
    if (lsHealthBadge) {
      lsHealthBadge.textContent = data.status || "unknown";
      lsHealthBadge.className = `status-badge ${lsHealthClass(data.status)}`;
    }
    renderLsStatCards(data);
    renderLsHistoryPipelineOptions(Object.keys(data.pipelines || {}));
    renderLsPipelines(data.pipelines);
  } catch (err) {
    if (lsHealthBadge) {
      lsHealthBadge.textContent = "unreachable";
      lsHealthBadge.className = "status-badge status-failed";
    }
    showError(err.message);
  }
}

// Matches Logstash's own bracketed timestamp, e.g. "...64401:[2026-08-07T10:40:01,441][WARN]..."
// -- searched anywhere in the line (not anchored) so an optional leading
// "NNNNN:" line-number prefix from grep -n doesn't matter.
const LS_LOG_TS_RE = /\[(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})/;

function filterLsLogByDate(rawText) {
  const startVal = lsLogDateStart.value;
  const endVal = lsLogDateEnd.value;
  if (!startVal && !endVal) return rawText;

  const startMs = startVal ? new Date(startVal).getTime() : -Infinity;
  const endMs = endVal ? new Date(endVal).getTime() : Infinity;

  let lastTs = null;
  const kept = [];
  rawText.split("\n").forEach((line) => {
    const match = line.match(LS_LOG_TS_RE);
    if (match) lastTs = new Date(`${match[1]}T${match[2]}`).getTime();
    // A line with no timestamp of its own (e.g. a stack-trace continuation)
    // inherits whatever timestamp came before it, so a date filter doesn't
    // slice a multi-line entry in half. Lines before any timestamp appears
    // at all are kept too, rather than silently dropped.
    if (lastTs === null || (lastTs >= startMs && lastTs <= endMs)) {
      kept.push(line);
    }
  });
  return kept.join("\n");
}

function renderLsLogOutput(emptyMessage) {
  lsLogOutput.textContent = filterLsLogByDate(lsLogRawContent) || emptyMessage;
  lsLogOutput.scrollTop = lsLogOutput.scrollHeight;

  const startVal = lsLogDateStart.value;
  const endVal = lsLogDateEnd.value;
  const parts = [];
  if (startVal) parts.push(`from ${startVal.replace("T", " ")}`);
  if (endVal) parts.push(`to ${endVal.replace("T", " ")}`);
  updateFilterNote(lsLogDateActiveNote, parts.length ? [parts.join(" ")] : []);
}

async function loadLsLog() {
  const path = lsLogPathInput.value.trim();
  const pattern = lsGrepInput.value.trim();
  const lines = lsLogLinesSelect.value;
  if (!path) return;

  lsLogOutput.textContent = "Loading...";
  try {
    let url = `${API_BASE}/logs?path=${encodeURIComponent(path)}&lines=${encodeURIComponent(lines)}`;
    if (pattern) url += `&grep=${encodeURIComponent(pattern)}`;
    const res = await fetch(url);
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to load log");
    lsLogRawContent = data.content || "";
    renderLsLogOutput(pattern ? "(no lines matched)" : "(empty file)");
  } catch (err) {
    lsLogOutput.textContent = `Error: ${err.message}`;
  }
}

// ============================================================
// Logstash view: Elasticsearch Errors (reads Logstash's own log file for
// output-side bulk-request rejections, e.g. 413 -- see
// ssh_manager.parse_es_bulk_errors / aggregate_es_bulk_errors, and
// app.py's api_logstash_es_errors). Read-only against the target host,
// same live SSH connection as everything else on this page.
// ============================================================

function renderEsErrorRows(groups) {
  if (!lsEsErrorRows) return;
  lsEsErrorRows.innerHTML = "";
  if (lsEsErrorSample) lsEsErrorSample.classList.add("d-none");

  if (!groups || !groups.length) {
    lsEsErrorRows.innerHTML = `<tr class="empty-row"><td colspan="6">No Elasticsearch bulk-request rejections found in the checked window.</td></tr>`;
    return;
  }

  groups.forEach((g) => {
    const tr = document.createElement("tr");
    [g.pipeline_id, g.host, g.code, g.count, g.first_seen, g.last_seen].forEach((val, idx) => {
      const td = document.createElement("td");
      td.textContent = val;
      if (idx === 2) td.style.color = "var(--color-danger)";
      tr.appendChild(td);
    });
    tr.style.cursor = "pointer";
    tr.title = "Click to see a sample log line";
    tr.addEventListener("click", () => {
      if (!lsEsErrorSample) return;
      lsEsErrorSample.textContent = g.sample || "(no sample captured)";
      lsEsErrorSample.classList.remove("d-none");
    });
    lsEsErrorRows.appendChild(tr);
  });
}

async function loadEsErrors() {
  if (!lsEsErrorRows) return;
  const path = (lsEsErrorsPathInput && lsEsErrorsPathInput.value.trim()) || "/var/log/logstash/logstash-plain.log";
  lsEsErrorRows.innerHTML = `<tr class="empty-row"><td colspan="6">Loading&hellip;</td></tr>`;
  try {
    const res = await fetch(`${API_BASE}/logstash/es-errors?path=${encodeURIComponent(path)}`);
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to check Elasticsearch errors");
    renderEsErrorRows(data.groups);
  } catch (err) {
    lsEsErrorRows.innerHTML = `<tr class="empty-row"><td colspan="6">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function stopLsEsErrorsAutoRefresh() {
  if (lsEsErrorsTimer) {
    clearInterval(lsEsErrorsTimer);
    lsEsErrorsTimer = null;
  }
}

// ============================================================
// Logstash view: local pipeline history / time-range filter
// (reads back snapshots the dashboard recorded itself -- see
// db.record_logstash_snapshot; no SSH connection involved here)
//
// The filter row (pipeline select + range + quick-range chips) lives right
// under the stat cards and drives the SAME table as the live view below:
// "Refresh"/auto-refresh fills it with live per-pipeline stats, a quick-range
// chip or "Load" replaces it with historical snapshot rows instead.
// ============================================================

function formatSnapshotTime(unixSeconds) {
  return new Date(unixSeconds * 1000).toLocaleString();
}

// Shared by both the Logstash filter bar and the Start/Stop History filter bar.
function setActiveChip(chips, activeChip) {
  chips.forEach((chip) => chip.classList.toggle("active", chip === activeChip));
}

function updateFilterNote(noteEl, parts) {
  const text = parts.filter(Boolean).join(" &middot; ");
  if (!text) {
    noteEl.classList.add("d-none");
    noteEl.innerHTML = "";
  } else {
    noteEl.classList.remove("d-none");
    noteEl.innerHTML = text;
  }
}

function renderLsHistoryPipelineOptions(ids) {
  if (!lsPipelineOptions) return; // Pipeline Status page not granted -- its filter box doesn't exist.
  lsPipelineOptions.innerHTML = ids.map((id) => `<option value="${escapeHtml(id)}"></option>`).join("");
  // Was a hardcoded "130 pipelines" in the template -- wrong the moment any server's
  // pipeline count differs (which is most of the time). Keep it live off the same
  // data this function already renders instead of a number frozen from one snapshot.
  if (lsHistoryPipeline) {
    lsHistoryPipeline.placeholder = ids.length
      ? `Search pipeline (type to search ${ids.length} pipelines)…`
      : "Search pipeline…";
  }
}

function lsHealthFromSnapshot(s) {
  const workers = s.workers || 0;
  if (workers <= 0) return "down";
  if ((s.reload_failures || 0) > 0) return "issues";
  return "up";
}

function renderLsHistoryIntoMainTable(snapshots) {
  lsPipelineRows.innerHTML = "";
  if (!snapshots.length) {
    lsPipelineRows.innerHTML = '<tr class="empty-row"><td colspan="10">No snapshots recorded in this range.</td></tr>';
    return;
  }
  snapshots.forEach((s) => {
    const tr = document.createElement("tr");
    const timeTd = document.createElement("td");
    timeTd.textContent = formatSnapshotTime(s.captured_at);
    tr.appendChild(timeTd);

    const nameTd = document.createElement("td");
    nameTd.textContent = s.pipeline_id;
    tr.appendChild(nameTd);

    const statusTd = document.createElement("td");
    statusTd.innerHTML = lsPipelineHealthBadge(lsHealthFromSnapshot(s));
    tr.appendChild(statusTd);

    [
      s.workers,
      s.events_in,
      s.events_filtered,
      s.events_out,
      "—", // rate isn't meaningful across arbitrary historical gaps
      `${s.queue_type || "—"} (${s.queue_events ?? 0})`,
      s.reload_failures || 0,
    ].forEach((val, idx) => {
      const td = document.createElement("td");
      td.textContent = val;
      if (idx === 6 && Number(val) > 0) td.style.color = "var(--color-danger)";
      tr.appendChild(td);
    });
    lsPipelineRows.appendChild(tr);
  });
}

async function loadLsHistory(quickMinutes, chipEl) {
  const params = new URLSearchParams();
  const pipeline = lsHistoryPipeline.value.trim();
  if (pipeline) params.set("pipeline", pipeline);

  let rangeLabel;
  if (quickMinutes) {
    params.set("minutes", quickMinutes);
    lsHistoryStart.value = "";
    lsHistoryEnd.value = "";
    rangeLabel = chipEl ? chipEl.textContent : `last ${quickMinutes} min`;
  } else {
    if (lsHistoryStart.value) params.set("start", lsHistoryStart.value);
    if (lsHistoryEnd.value) params.set("end", lsHistoryEnd.value);
    rangeLabel = lsHistoryStart.value || lsHistoryEnd.value ? "custom range" : "all recorded history";
  }
  setActiveChip(lsHistoryChips, chipEl || null);
  updateFilterNote(lsFilterActiveNote, [rangeLabel, pipeline ? `pipeline: "${pipeline}"` : null]);

  stopLsStatsAutoRefresh();
  lsAutoRefresh.checked = false;
  lsPipelineRows.innerHTML = '<tr class="empty-row"><td colspan="10">Loading...</td></tr>';
  try {
    const res = await fetch(`${API_BASE}/logstash/history?${params.toString()}`);
    if ([401, 403, 409].includes(res.status)) return (window.location.href = "/servers");
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to load history");
    renderLsHistoryPipelineOptions(data.pipeline_ids || []);
    renderLsHistoryIntoMainTable(data.snapshots || []);
  } catch (err) {
    lsPipelineRows.innerHTML = `<tr class="empty-row"><td colspan="10">Error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function stopLsStatsAutoRefresh() {
  if (lsStatsTimer) {
    clearInterval(lsStatsTimer);
    lsStatsTimer = null;
  }
}

function stopLsLogAutoRefresh() {
  if (lsLogTimer) {
    clearInterval(lsLogTimer);
    lsLogTimer = null;
  }
}

function switchView(viewName) {
  navItems.forEach((item) => item.classList.toggle("active", item.dataset.view === viewName));
  views.forEach((view) => view.classList.toggle("d-none", view.id !== `${viewName}View`));

  // Pipeline Status and Pipeline Logs each own a separate auto-refresh timer now
  // that they're separate pages -- only stop the one for the tab being left.
  // Reload/Config Errors has no timer of its own; it just displays whatever
  // Pipeline Status last fetched. Both elements are null (not just hidden) for
  // a user not granted that page's permission (see index.html's {% if
  // can_view_pipeline_* %} guards) -- switchView still runs on every nav
  // click regardless, so these have to tolerate that.
  if (viewName !== "logstashStatus" && lsAutoRefresh) {
    stopLsStatsAutoRefresh();
    lsAutoRefresh.checked = false;
  }
  if (viewName !== "logstashLogs" && lsAutoRefreshLog) {
    stopLsLogAutoRefresh();
    lsAutoRefreshLog.checked = false;
  }
  if (viewName !== "logstashEsErrors" && lsEsErrorsAutoRefresh) {
    stopLsEsErrorsAutoRefresh();
    lsEsErrorsAutoRefresh.checked = false;
  }
}

navItems.forEach((item) => {
  item.addEventListener("click", () => {
    switchView(item.dataset.view);
    // Both Pipeline Status and Reload/Config Errors read from the same live
    // fetch, so either tab being opened first should trigger it.
    if ((item.dataset.view === "logstashStatus" || item.dataset.view === "logstashErrors") && !lsStatsLoadedOnce) {
      lsStatsLoadedOnce = true;
      loadLsStats();
    }
    // History is now its own page (previously loaded eagerly at the bottom of
    // the Services page on every load) -- load it lazily on first visit instead,
    // same pattern as Pipeline Status above.
    if (item.dataset.view === "serviceHistory" && !historyLoadedOnce) {
      historyLoadedOnce = true;
      loadServiceHistory(21600, document.querySelector("#historyQuickRanges .chip.active"));
    }
    if (item.dataset.view === "logstashEsErrors" && !lsEsErrorsLoadedOnce) {
      lsEsErrorsLoadedOnce = true;
      loadEsErrors();
    }
  });
});

// Everything in this section belongs to Pipeline Status / Reload-Errors /
// Pipeline Logs -- each element is entirely absent from the DOM (not just
// hidden) for a user not granted that page's permission (see index.html's
// {% if can_view_pipeline_* %} guards), so every reference here is
// null-checked. Without that, a user with e.g. only "Start / Stop Services"
// access would hit a null.addEventListener() on script load and the crash
// would abort every listener attached AFTER it too -- including the ones the
// Services page itself needs (refreshBtn, searchInput, history) below.
if (lsRefreshBtn) lsRefreshBtn.addEventListener("click", loadLsStats);
if (lsStatCards) {
  // Click Up/Issues/Down to narrow the pipeline table to just that status;
  // click the same card again (or "Pipelines") to clear it. Re-renders from
  // the already-fetched data -- no re-fetch needed for a filter toggle.
  lsStatCards.addEventListener("click", (e) => {
    const card = e.target.closest(".stat-card[data-status]");
    if (!card || !lsLastStatsData) return;
    const status = card.dataset.status;
    lsStatusFilter = lsStatusFilter === status ? null : status;
    renderLsStatCards(lsLastStatsData);
    renderLsPipelines(lsLastStatsData.pipelines);
  });
}
if (lsAutoRefresh) {
  lsAutoRefresh.addEventListener("change", () => {
    stopLsStatsAutoRefresh();
    if (lsAutoRefresh.checked) {
      loadLsStats();
      lsStatsTimer = setInterval(loadLsStats, 10000);
    }
  });
}

if (lsLoadLogBtn) lsLoadLogBtn.addEventListener("click", loadLsLog);
if (lsGrepInput) {
  lsGrepInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadLsLog();
  });
}
if (lsLogPathInput) {
  lsLogPathInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadLsLog();
  });
}
if (lsAutoRefreshLog) {
  lsAutoRefreshLog.addEventListener("change", () => {
    stopLsLogAutoRefresh();
    if (lsAutoRefreshLog.checked) {
      loadLsLog();
      lsLogTimer = setInterval(loadLsLog, 5000);
    }
  });
}
lsChips.forEach((chip) => {
  chip.addEventListener("click", () => {
    lsGrepInput.value = chip.dataset.pattern || "";
    loadLsLog();
  });
});

if (lsEsErrorsRefreshBtn) lsEsErrorsRefreshBtn.addEventListener("click", loadEsErrors);
if (lsEsErrorsLoadBtn) lsEsErrorsLoadBtn.addEventListener("click", loadEsErrors);
if (lsEsErrorsPathInput) {
  lsEsErrorsPathInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadEsErrors();
  });
}
if (lsEsErrorsAutoRefresh) {
  lsEsErrorsAutoRefresh.addEventListener("change", () => {
    stopLsEsErrorsAutoRefresh();
    if (lsEsErrorsAutoRefresh.checked) {
      loadEsErrors();
      lsEsErrorsTimer = setInterval(loadEsErrors, 30000);
    }
  });
}

// Date filter re-slices the already-loaded content client-side -- no re-fetch.
if (lsLogDateStart) lsLogDateStart.addEventListener("change", () => renderLsLogOutput("(empty file)"));
if (lsLogDateEnd) lsLogDateEnd.addEventListener("change", () => renderLsLogOutput("(empty file)"));
if (lsLogDateClearBtn) {
  lsLogDateClearBtn.addEventListener("click", () => {
    lsLogDateStart.value = "";
    lsLogDateEnd.value = "";
    renderLsLogOutput("(empty file)");
  });
}

if (lsHistoryLoadBtn) lsHistoryLoadBtn.addEventListener("click", () => loadLsHistory());
lsHistoryChips.forEach((chip) => {
  chip.addEventListener("click", () => loadLsHistory(chip.dataset.minutes, chip));
});
if (lsHistoryClearBtn) {
  lsHistoryClearBtn.addEventListener("click", () => {
    lsHistoryStart.value = "";
    lsHistoryEnd.value = "";
    setActiveChip(lsHistoryChips, null);
    updateFilterNote(lsFilterActiveNote, [lsHistoryPipeline.value.trim() ? `pipeline: "${lsHistoryPipeline.value.trim()}"` : null]);
    loadLsStats();
  });
}

refreshBtn.addEventListener("click", loadServices);
searchInput.addEventListener("input", applySearchFilter);

historyRefreshBtn.addEventListener("click", () => loadServiceHistory());
historyLoadBtn.addEventListener("click", () => loadServiceHistory());
historyChips.forEach((chip) => {
  chip.addEventListener("click", () => loadServiceHistory(chip.dataset.minutes, chip));
});

loadServices();
