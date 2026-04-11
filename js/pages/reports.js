// /js/pages/reports.js
(() => {
  "use strict";

  window.pages = window.pages || {};

  const REPORT_PROXY = "/api/report.php";

  // Persist state across SPA navigation (important: avoids multiple listeners)
  const STATE = (window.pages.reports_state = window.pages.reports_state || {
    dataset: null,
    reports: [],
    reportById: new Map(),
    handlersBound: false
  });

  // ---------------- utils ----------------
  const escapeHtml = (v) => {
    const s = String(v ?? "");
    return s
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  };

  const num = (v, fallback = 0) => {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  };

  const formatDate = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toISOString().replace("T", " ").slice(0, 19);
  };

  const pick = (obj, keys, fallback = undefined) => {
    for (const k of keys) {
      if (obj && obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
    }
    return fallback;
  };

  const safeStr = (v) => (v === null || v === undefined ? "" : String(v));

  // ---------------- RU labels ----------------
  const THREAT_RU = {
    Log: "Инфо",
    None: "Нет",
    Low: "Низкий",
    Medium: "Средний",
    High: "Высокий",
    Critical: "Критический"
  };

  const STATUS_RU = {
    open: "Открыто",
    in_progress: "В работе",
    accepted_risk: "Риск принят",
    investigating: "Расследование",
    resolved: "Исправлено",
    closed: "Закрыто",
    false_positive: "Ложное",
    other: "Прочее"
  };

  const threatRu = (t) => THREAT_RU[String(t || "").trim()] || String(t || "—");
  const statusRu = (s) => {
    const k = String(s || "").trim().toLowerCase().replace(/\s+/g, "_");
    return STATUS_RU[k] || String(s || "—");
  };

  /** Ключ серьёзности для бейджей (OpenVAS threat + CVSS). */
  function getSeverityKey(f) {
    const t = String(f.threat || "").trim().toLowerCase();
    if (t.includes("critical") || t.includes("критич")) return "critical";
    if (t === "high" || t.includes("high") || t.includes("высок")) return "high";
    if (t === "medium" || t.includes("medium") || t.includes("средн")) return "medium";
    if (t === "low" || t.includes("low") || t.includes("низк")) return "low";
    if (t === "log" || t === "none" || t === "info" || t.includes("инфо")) return "info";
    const cv = num(f.cvss, 0);
    if (cv >= 9) return "critical";
    if (cv >= 7) return "high";
    if (cv >= 4) return "medium";
    if (cv > 0) return "low";
    return "info";
  }

  function threatBadgeHtml(f) {
    const key = getSeverityKey(f);
    const label = threatRu(f.threat);
    return `<span class="reports-badge reports-badge--${escapeHtml(key)}">${escapeHtml(label)}</span>`;
  }

  function statusBadgeHtml(f) {
    const sk = String(f.status || "open").trim().toLowerCase().replace(/\s+/g, "_");
    const cls =
      sk === "open"
        ? "status-open"
        : sk === "in_progress"
          ? "status-in-progress"
          : sk === "accepted_risk"
            ? "status-accepted-risk"
            : sk === "investigating"
              ? "status-investigating"
              : sk === "resolved"
                ? "status-resolved"
                : sk === "false_positive"
                  ? "status-false-positive"
                  : "status-other";
    return `<span class="status ${cls}">${escapeHtml(statusRu(f.status))}</span>`;
  }

  function cvssPillClass(f) {
    return `reports-finding__cvss--${getSeverityKey(f)}`;
  }

  // ---------------- Toast ----------------
  const ensureToastHost = () => {
    let host = document.getElementById("reports-toast-host");
    if (host) return host;

    host = document.createElement("div");
    host.id = "reports-toast-host";
    host.style.cssText = [
      "position:fixed",
      "right:16px",
      "bottom:16px",
      "z-index:10000",
      "display:flex",
      "flex-direction:column",
      "gap:8px",
      "max-width:min(520px, calc(100vw - 32px))"
    ].join(";");
    document.body.appendChild(host);
    return host;
  };

  const showToast = (message, tone = "info") => {
    const host = ensureToastHost();

    const el = document.createElement("div");
    el.style.cssText = [
      "background:rgba(20,20,20,.92)",
      "color:#fff",
      "border:1px solid rgba(255,255,255,.14)",
      "border-radius:12px",
      "padding:10px 12px",
      "box-shadow:0 12px 30px rgba(0,0,0,.35)"
    ].join(";");

    const title =
      tone === "error" ? "Ошибка" :
      tone === "success" ? "Готово" :
      "Инфо";

    el.innerHTML = `
      <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start;">
        <div>
          <div style="font-weight:900; margin-bottom:2px;">${escapeHtml(title)}</div>
          <div style="opacity:.92; white-space:pre-wrap;">${escapeHtml(message)}</div>
        </div>
        <button class="btn btn-sm btn-secondary" style="line-height:1; padding:.25rem .5rem;">✕</button>
      </div>
    `;

    el.querySelector("button").addEventListener("click", () => el.remove());
    host.appendChild(el);
    window.setTimeout(() => el.remove(), 4000);
  };

  // ---------------- Modal ----------------
  const ensureModal = () => {
    let el = document.getElementById("reports-modal");
    if (el) return el;

    el = document.createElement("div");
    el.id = "reports-modal";
    el.className = "reports-modal-root";
    el.setAttribute("role", "presentation");

    el.innerHTML = `
      <div class="reports-modal__dialog" role="dialog" aria-modal="true" aria-labelledby="reports-modal-title">
        <header class="reports-modal__head">
          <h2 id="reports-modal-title" class="reports-modal__title"></h2>
          <button type="button" id="reports-modal-close" class="reports-modal__close" aria-label="Закрыть">✕</button>
        </header>
        <div id="reports-modal-body" class="reports-modal__body"></div>
      </div>
    `;

    document.body.appendChild(el);

    const close = () => {
      el.classList.remove("is-open");
      const t = document.getElementById("reports-modal-title");
      const b = document.getElementById("reports-modal-body");
      if (t) t.textContent = "";
      if (b) b.innerHTML = "";
      document.body.style.overflow = "";
    };

    el.addEventListener("click", (e) => {
      if (e.target === el) close();
    });
    document.getElementById("reports-modal-close").addEventListener("click", close);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && el.classList.contains("is-open")) close();
    });

    el.open = (title, html) => {
      const titleEl = document.getElementById("reports-modal-title");
      const bodyEl = document.getElementById("reports-modal-body");
      if (titleEl) titleEl.textContent = title || "Отчёт";
      if (bodyEl) bodyEl.innerHTML = html || "";
      el.classList.add("is-open");
      document.body.style.overflow = "hidden";
    };

    el.close = close;
    return el;
  };

  const openModal = (title, html) => ensureModal().open(title, html);

  // ---------------- Dataset (через защищённый API) ----------------
  const loadDataset = async () => {
    if (!window.dataLoader || typeof dataLoader.loadDataset !== "function") {
      throw new Error("dataLoader недоступен");
    }
    await dataLoader.loadDataset(true);
    const data = dataLoader.data;
    if (!data || !Array.isArray(data.assets) || !Array.isArray(data.findings)) {
      throw new Error("Неверный формат датасета: ожидаются поля assets[] и findings[]");
    }
    return {
      assets: data.assets,
      findings: data.findings,
    };
  };

  // ---------------- Normalize ----------------
  const normalizeAsset = (a) => {
    const assetId = pick(a, ["asset_id", "assetid", "assetId", "id"], "");
    const hostname = pick(a, ["hostname", "host"], "");
    const ip = pick(a, ["ip", "ip_address", "ipAddress"], "");
    const ownerteam = pick(a, ["owner_team", "ownerteam", "ownerTeam", "department", "dept"], "unknown");
    return { assetId, hostname, ip, ownerteam: String(ownerteam || "unknown").trim() || "unknown" };
  };

  const normalizeFinding = (f) => {
    if (f && f.status_key !== undefined) {
      const plugin = safeStr(f.name || f.title || "");
      const threat = safeStr(f.raw?.threat || f.severity || "");
      const status = safeStr(f.status_key || f.status || "");
      const cvss = num(f.cvss_score, 0);
      const detectedAt = safeStr(f.detectedat || "");
      const hostname = safeStr(f.hostname || "");
      const ip = safeStr(f.ip || "");
      const port = safeStr(pick(f.raw || {}, ["port", "port_num"], ""));
      const assetId = safeStr(f.asset_id || "");
      return {
        plugin,
        threat,
        status,
        cvss,
        detectedAt,
        hostname,
        ip,
        port,
        assetId,
        host: hostname || ip || assetId || ""
      };
    }

    const plugin = pick(f, ["plugin_name", "pluginname", "pluginName", "plugin"], "");
    const threat = pick(f, ["threat"], "");
    const status = pick(f, ["status"], "");
    const cvss = num(pick(f, ["cvss_base", "cvssbase", "cvssBase", "cvss"], 0), 0);

    const detectedAt = pick(f, ["detected_at", "detectedat", "detectedAt"], "");
    const hostname = pick(f, ["hostname", "host"], "");
    const ip = pick(f, ["ip"], "");
    const port = pick(f, ["port"], "");
    const assetId = pick(f, ["asset_id", "assetid", "assetId"], "");

    return {
      plugin,
      threat,
      status,
      cvss,
      detectedAt,
      hostname,
      ip,
      port,
      assetId,
      host: hostname || ip || assetId || ""
    };
  };

  const buildIndex = (assetsNorm) => {
    const byAssetId = new Map();
    const byHostOrIp = new Map();
    for (const a of assetsNorm) {
      if (a.assetId) byAssetId.set(a.assetId, a);
      if (a.hostname) byHostOrIp.set(String(a.hostname).toLowerCase(), a);
      if (a.ip) byHostOrIp.set(String(a.ip).toLowerCase(), a);
    }
    return { byAssetId, byHostOrIp };
  };

  const attachAssetInfo = (finding, index) => {
    const a1 = finding.assetId ? index.byAssetId.get(finding.assetId) : null;
    const a2 = finding.hostname ? index.byHostOrIp.get(String(finding.hostname).toLowerCase()) : null;
    const a3 = finding.ip ? index.byHostOrIp.get(String(finding.ip).toLowerCase()) : null;
    const a = a1 || a2 || a3;
    return { ...finding, ownerteam: a ? a.ownerteam : "unknown" };
  };

  // ---------------- Stats ----------------
  const uniqCount = (items, keyFn) => new Set(items.map(keyFn)).size;

  const computeStats = (findings) => {
    const total = findings.length;
    const open = findings.filter((f) => String(f.status).trim().toLowerCase() === "open");
    const openCount = open.length;
    const openHighPlus = open.filter((f) => num(f.cvss, 0) >= 7).length;

    const hostsAll = uniqCount(findings, (f) => (f.hostname || f.ip || f.host || "").toLowerCase());
    const hostsOpen = uniqCount(open, (f) => (f.hostname || f.ip || f.host || "").toLowerCase());

    return { total, openCount, openHighPlus, hostsAll, hostsOpen };
  };

  // ---------------- API ----------------
  const pingReportApi = async () => {
    const res = await fetch(`${REPORT_PROXY}?ping=1`, {
      credentials: "same-origin",
      cache: "no-store"
    });
    if (!res.ok) throw new Error(`API HTTP ${res.status}`);
    const j = await res.json().catch(() => null);
    if (!j || j.ok !== true) throw new Error("Сервис отчётов недоступен");
    return true;
  };

  const sendPdfToTelegram = async (payload) => {
    const res = await fetch(REPORT_PROXY, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`send_report HTTP ${res.status}${t ? `: ${t.slice(0, 300)}` : ""}`);
    }
    return res.json().catch(() => ({}));
  };

  // ---------------- UI builders ----------------
  const kpiTile = (label, value, hint) => `
    <div class="reports-kpi">
      <div class="reports-kpi__label">${escapeHtml(label)}</div>
      <div class="reports-kpi__value">${escapeHtml(String(value))}</div>
      ${hint ? `<div class="reports-kpi__hint">${escapeHtml(hint)}</div>` : ""}
    </div>
  `;

  const renderReportsTable = (reports) => {
    const rows = reports.map((r) => `
      <tr class="reports-page-table__row">
        <td>
          <div class="reports-page-table__title">${escapeHtml(r.title)}</div>
          <div class="reports-page-table__desc">${escapeHtml(r.description || "")}</div>
        </td>
        <td class="reports-page-table__dept"><code>${escapeHtml(r.department)}</code></td>
        <td class="reports-page-actions">
          <button type="button" class="btn btn--primary btn--sm" data-action="view" data-report-id="${escapeHtml(r.id)}">Просмотр</button>
          <button type="button" class="btn btn--secondary btn--sm" data-action="send-pdf" data-report-id="${escapeHtml(r.id)}">PDF в Telegram</button>
        </td>
      </tr>
    `).join("");

    return `
      <div class="reports-page-table-wrap">
        <table class="reports-page-table">
          <thead><tr><th>Отчёт</th><th>Область / отдел</th><th>Действия</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="3" class="reports-page-table__empty">Нет доступных отчётов</td></tr>`}</tbody>
        </table>
      </div>
    `;
  };

  const dashboardHtml = (rep) => {
    const stats = computeStats(rep.findings);

    const openTop = rep.findings
      .filter((f) => String(f.status).trim().toLowerCase() === "open")
      .sort((a, b) => (b.cvss - a.cvss) || String(b.detectedAt).localeCompare(String(a.detectedAt)))
      .slice(0, 25);

    const findingCards = openTop.length
      ? openTop
          .map((f) => {
            const host = f.hostname || f.ip || f.host || "—";
            const port = f.port || "—";
            return `
      <article class="reports-finding">
        <div class="reports-finding__row">
          <span class="reports-finding__cvss ${cvssPillClass(f)}">${escapeHtml(String(f.cvss))}</span>
          ${threatBadgeHtml(f)}
          ${statusBadgeHtml(f)}
        </div>
        <div class="reports-finding__title">${escapeHtml(f.plugin || "—")}</div>
        <div class="reports-finding__meta">
          <span><strong>Хост</strong> <code>${escapeHtml(host)}</code></span>
          <span><strong>Порт</strong> <code>${escapeHtml(port)}</code></span>
          <span><strong>Обнаружено</strong> ${escapeHtml(formatDate(f.detectedAt))}</span>
        </div>
      </article>`;
          })
          .join("")
      : `<p class="reports-view__hint" style="margin:0;">Нет открытых уязвимостей по этому отчёту.</p>`;

    return `
      <div class="reports-view">
        <p class="reports-view__lead">${escapeHtml(rep.description || "")}</p>
        <div class="reports-view__actions">
          <button type="button" class="btn btn--primary" data-action="send-pdf" data-report-id="${escapeHtml(rep.id)}">Отправить PDF в Telegram</button>
          <button type="button" class="btn btn--secondary" data-action="close-modal">Закрыть</button>
        </div>
        <p class="reports-view__hint">PDF отправляется через сервер: <code>${escapeHtml(REPORT_PROXY)}</code></p>

        <div class="reports-kpi-grid">
          ${kpiTile("Всего находок", stats.total, "по всем статусам")}
          ${kpiTile("Открытые", stats.openCount, "статус Open")}
          ${kpiTile("Open, CVSS ≥ 7", stats.openHighPlus, "высокая критичность")}
          ${kpiTile("Хосты", stats.hostsAll, `с открытыми: ${stats.hostsOpen}`)}
        </div>

        <h3 class="reports-view__section-title">Открытые уязвимости (до 25)</h3>
        <div class="reports-findings-list">${findingCards}</div>
      </div>
    `;
  };

  // ---------------- Build reports ----------------
  const buildReports = (data) => {
    const assetsNorm = (data.assets || []).map(normalizeAsset);
    const idx = buildIndex(assetsNorm);

    const findingsNorm = (data.findings || [])
      .map(normalizeFinding)
      .map((f) => attachAssetInfo(f, idx));

    const reports = [];

    // Global
    reports.push({
      id: "dashboard",
      department: "all",
      title: "Отчёт: все отделы",
      description: "Сводка по всем уязвимостям и хостам.",
      findings: findingsNorm
    });

    // Departments
    const teams = [...new Set(assetsNorm.map((a) => String(a.ownerteam || "unknown").trim() || "unknown"))]
      .sort((a, b) => a.localeCompare(b));

    for (const team of teams) {
      const deptFindings = findingsNorm.filter((f) => String(f.ownerteam || "unknown").trim() === team);
      reports.push({
        id: `dept:${team}`,
        department: team,
        title: `Отчёт: ${team}`,
        description: "Сводка по уязвимостям хостов отдела.",
        findings: deptFindings
      });
    }

    return reports;
  };

  // ---------------- One-time global handlers ----------------
  const bindHandlersOnce = () => {
    if (STATE.handlersBound) return;
    STATE.handlersBound = true;

    document.body.addEventListener("click", async (e) => {
      const btn = e.target && e.target.closest ? e.target.closest("button[data-action]") : null;
      if (!btn) return;

      const action = btn.getAttribute("data-action");

      if (action === "close-modal") {
        const m = document.getElementById("reports-modal");
        if (m && typeof m.close === "function") m.close();
        return;
      }

      const reportId = btn.getAttribute("data-report-id") || "";
      const rep = STATE.reportById.get(reportId);
      if (!rep) return;

      // anti-doubleclick and anti-multi-trigger
      if (btn.dataset.busy === "1") return;

      if (action === "view") {
        openModal(rep.title, dashboardHtml(rep));
        return;
      }

      if (action === "send-pdf") {
        try {
          btn.dataset.busy = "1";
          btn.disabled = true;

          const stats = computeStats(rep.findings);

          const openTop = rep.findings
            .filter((f) => String(f.status).trim().toLowerCase() === "open")
            .sort((a, b) => (b.cvss - a.cvss) || String(b.detectedAt).localeCompare(String(a.detectedAt)))
            .slice(0, 50)
            .map((f) => ({
              cvss: f.cvss,
              threat: threatRu(f.threat),
              threat_key:
                (String(f.threat).trim() === "High" || Number(f.cvss) >= 7) ? "high" :
                (String(f.threat).trim() === "Medium") ? "medium" :
                (String(f.threat).trim() === "Low") ? "low" : "info",
              status: statusRu(f.status),
              status_key: safeStr(f.status).trim().toLowerCase().replace(/\s+/g, "_") || "other",
              host: f.hostname || f.ip || f.host || "unknown",
              port: f.port || "",
              plugin: f.plugin || "",
              detected: formatDate(f.detectedAt)
            }));

          const payload = {
            department: rep.department || "unknown",
            kpis: {
              total: stats.total,
              open: stats.openCount,
              open_high7: stats.openHighPlus,
              hosts: stats.hostsAll,
              hosts_open: stats.hostsOpen
            },
            open_rows: openTop
          };

          showToast("Формирую и отправляю PDF…", "info");
          await sendPdfToTelegram(payload);
          showToast("PDF отправлен в Telegram.", "success");
        } catch (err) {
          showToast(err?.message ? String(err.message) : String(err), "error");
        } finally {
          btn.disabled = false;
          delete btn.dataset.busy;
        }
      }
    }, { passive: true });
  };

  // ---------------- Page API ----------------
  window.pages.reports = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">Отчёты</div>
          <p class="reports-page__intro">
            Готовые срезы по отделам (из поля <code>owner_team</code> активов) и сводный отчёт.
            Просмотр — интерактивная сводка; PDF уходит в Telegram через защищённый прокси.
          </p>

          <div class="card findings-layout reports-page__shell" style="margin-top:20px;">
            <section class="findings-toolbar reports-toolbar" aria-label="Действия">
              <div class="reports-toolbar__row">
                <button type="button" id="rep-reload" class="btn btn--secondary btn--sm">Обновить датасет</button>
                <span id="rep-status" class="reports-toolbar__status">—</span>
              </div>
              <div class="reports-toolbar__meta">
                <span>API данных: <code>/api/dataset.php</code></span>
                <span>PDF: <code>${escapeHtml(REPORT_PROXY)}</code> · <span id="rep-api-status">проверка…</span></span>
              </div>
            </section>

            <section class="findings-main reports-page__list-wrap">
              <div id="reports-list" class="reports-page__list-inner">
                <div class="reports-page__loading">Загрузка…</div>
              </div>
            </section>
          </div>
        </div>
      `;
    },

    async init() {
      bindHandlersOnce();

      const statusEl = document.getElementById("rep-status");
      const apiStatusEl = document.getElementById("rep-api-status");
      const listHost = document.getElementById("reports-list");
      const reloadBtn = document.getElementById("rep-reload");

      const renderList = () => {
        listHost.innerHTML = renderReportsTable(STATE.reports);
      };

      const reload = async () => {
        statusEl.textContent = "Загрузка датасета…";
        STATE.dataset = await loadDataset();

        STATE.reports = buildReports(STATE.dataset);
        STATE.reportById = new Map(STATE.reports.map((r) => [r.id, r]));

        statusEl.textContent = `Готово • assets: ${STATE.dataset.assets.length} • findings: ${STATE.dataset.findings.length}`;
        renderList();
      };

      // ping API
      (async () => {
        try {
          await pingReportApi();
          apiStatusEl.textContent = "OK";
        } catch (_) {
          apiStatusEl.textContent = "недоступен";
        }
      })();

      reloadBtn?.addEventListener("click", async () => {
        try {
          reloadBtn.disabled = true;
          listHost.innerHTML = `<div class="reports-page__loading">Загрузка…</div>`;
          await reload();
          showToast("Датасет обновлён.", "success");
        } catch (e) {
          statusEl.textContent = "Ошибка загрузки";
          listHost.innerHTML = `
            <div class="reports-page__error">
              <div class="reports-page__error-title">Ошибка</div>
              <div class="reports-page__error-text">${escapeHtml(e?.message || String(e))}</div>
            </div>
          `;
          showToast("Не удалось загрузить датасет.", "error");
        } finally {
          reloadBtn.disabled = false;
        }
      });

      try {
        await reload();
      } catch (e) {
        statusEl.textContent = "Ошибка загрузки";
        listHost.innerHTML = `
          <div class="reports-page__error">
            <div class="reports-page__error-title">Ошибка</div>
            <div class="reports-page__error-text">${escapeHtml(e?.message || String(e))}</div>
          </div>
        `;
      }
    }
  };
})();
