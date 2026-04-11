// js/pages/findings.js
(() => {
  "use strict";
  window.pages = window.pages || {};

  // ===== RU LABELS =====
  const RU = {
    title: "Уязвимости",
    filters: {
      status: "Статус",
      department: "Подразделение",
      host: "Хост",
      search: "Поиск",
      reset: "Сбросить",
    },
    placeholders: {
      search: "CVE, плагин, порт, хост…",
    },
    summary: {
      showing: (a, b, t) => `Показаны ${a}–${b} из ${t}`,
      empty: "По выбранным фильтрам ничего не найдено",
      loading: "Загрузка…",
      noFindings: "Уязвимости не найдены",
    },
    table: {
      asset: "Хост",
      finding: "Уязвимость",
      severity: "Критичность",
      cvss: "CVSS",
      status: "Статус",
    },
    severity: {
      critical: "Критический",
      high: "Высокий",
      medium: "Средний",
      low: "Низкий",
      info: "Инфо",
    },
    status: {
      open: "Открыто",
      in_progress: "В работе",
      accepted_risk: "Риск принят",
      investigating: "Расследование",
      resolved: "Устранено",
      false_positive: "Ложноположительное",
      other: "Прочее",
    },
    chips: {
      all: "Все",
      critical: "Критические",
      high: "Высокие",
      medium: "Средние",
      low: "Низкие",
      info: "Инфо",
    },
    pagination: {
      prev: "← Назад",
      next: "Вперёд →",
      page: (p, t, n) => `Страница ${p} / ${t} · ${n} записей`,
    },
    modal: {
      title: "Информация об уязвимости",
      close: "Закрыть",
      copy: "Копировать JSON",
      copied: "Скопировано",
      empty: "Нет данных",
      sectionRaw: "Сырой объект",
      sectionSummary: "Краткое описание",
      sectionDescription: "Описание",
      sectionSolution: "Рекомендации",
    },
    fields: {
      name: "Название",
      host: "Хост",
      port: "Порт",
      port_num: "Номер порта",
      proto: "Протокол",
      severity: "Критичность",
      status: "Статус",
      cvss: "CVSS",
      family: "Семейство",
      nvt: "NVT OID",
      qod: "QoD",
      cve: "CVE",
      threat: "Threat",
      detected: "Обнаружено",
    },
  };

  const COLORS = {
    critical: "#F44336",
    high: "#FF9800",
    medium: "#FFC107",
    low: "#4CAF50",
    info: "#2196F3",
    all: "rgba(255,255,255,.55)",
  };

  // ===== HELPERS =====
  function safeStr(v) {
    return v === null || v === undefined ? "" : String(v);
  }
  function lower(v) {
    return safeStr(v).trim().toLowerCase();
  }
  function escapeHtml(str) {
    return safeStr(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
  function toNum(v, fallback = 0) {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  }
  function uniq(arr) {
    return Array.from(new Set((arr || []).filter(Boolean)));
  }

  // --- lock/unlock body scroll while modal open ---
  function lockBodyScroll(lock) {
    const b = document.body;
    if (lock) {
      if (b.dataset.prevOverflow === undefined) b.dataset.prevOverflow = b.style.overflow || "";
      b.style.overflow = "hidden";
    } else {
      b.style.overflow = b.dataset.prevOverflow || "";
      delete b.dataset.prevOverflow;
    }
  }

  function sevLabel(sev) {
    const s = lower(sev) || "info";
    return RU.severity[s] || RU.severity.info;
  }

  function statusLabel(st) {
    const s = lower(st) || "open";
    if (s === "false positive" || s === "false_positive") return RU.status.false_positive;
    return RU.status[s] || RU.status.other;
  }

  function statusLabelForFinding(f) {
    const key = f.status_key || lower(f.status) || "open";
    if (RU.status[key]) return RU.status[key];
    return safeStr(f.status_display || key);
  }

  function getAssetLabel(f) {
    return (
      safeStr(
        f.affected_asset ||
          f.affectedAsset ||
          f.hostname ||
          f.ip ||
          f.assetname ||
          f.asset_name ||
          f.assetid ||
          "-"
      ).trim() || "-"
    );
  }

  function getFindingLabel(f) {
    return (
      safeStr(
        f.title || f.pluginname || f.plugin_name || f.name || f.nvt_oid || f.nvtoid || "-"
      ).trim() || "-"
    );
  }

  // ---- FIX: port helpers (учитываем raw + port_num/proto) ----
  function getPortParts(f) {
    const raw = f && typeof f === "object" ? f.raw : null;

    const portStr = safeStr(
      f.port || f.hostport || f.service || raw?.port || raw?.hostport || raw?.service || ""
    ).trim();

    const portNum = toNum(
      f.port_num ?? f.portnum ?? f.portNum ?? raw?.port_num ?? raw?.portnum ?? raw?.portNum ?? NaN,
      NaN
    );

    const proto = safeStr(f.proto || f.protocol || raw?.proto || raw?.protocol || "").trim();

    return { portStr, portNum: Number.isFinite(portNum) ? portNum : null, proto: proto || "" };
  }

  function getPortDisplay(f) {
    const { portStr, portNum, proto } = getPortParts(f);
    if (portStr) return portStr;
    if (portNum !== null) return proto ? `${portNum}/${proto}` : String(portNum);
    return "";
  }

  function getCvss(f) {
    const n = toNum(f.cvss_score ?? f.cvssbase ?? f.cvss_base ?? f.cvssBase ?? 0, 0);
    return n.toFixed(1);
  }

  function pickTextField(f, keys) {
    for (const k of keys) {
      const v = safeStr(f?.[k]).trim();
      if (v) return v;
    }
    const raw = f && typeof f === "object" ? f.raw : null;
    for (const k of keys) {
      const v = safeStr(raw?.[k]).trim();
      if (v) return v;
    }
    return "";
  }

  function extractCves(f) {
    const raw = f && typeof f === "object" ? f.raw : null;

    const direct = []
      .concat(safeStr(f.cve || raw?.cve || "").split(/[,\s]+/))
      .concat(safeStr(f.cve_id || raw?.cve_id || "").split(/[,\s]+/))
      .concat(safeStr(f.cveid || raw?.cveid || "").split(/[,\s]+/))
      .concat(Array.isArray(f.cves) ? f.cves : [])
      .concat(Array.isArray(f.cveIds) ? f.cveIds : [])
      .concat(Array.isArray(raw?.cves) ? raw.cves : [])
      .concat(Array.isArray(raw?.cveIds) ? raw.cveIds : []);

    const fromXref = []
      .concat(safeStr(f.xref || raw?.xref || "").split(/[,\s]+/))
      .concat(safeStr(f.xrefs || raw?.xrefs || "").split(/[,\s]+/))
      .concat(safeStr(f.refs || raw?.refs || "").split(/[,\s]+/));

    return uniq(direct.concat(fromXref))
      .map((x) => x.trim())
      .filter((x) => /^CVE-\d{4}-\d+$/i.test(x));
  }

  function uniqHosts(findings) {
    const set = new Set();
    (findings || []).forEach((f) => {
      const host = getAssetLabel(f);
      if (host && host !== "-") set.add(host);
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b));
  }

  function uniqDepartments(findings) {
    const set = new Set();
    (findings || []).forEach((f) => {
      const d = safeStr(f.owner_team || f.department).trim();
      if (d) set.add(d);
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b, "ru"));
  }

  function matchesQuery(f, q) {
    if (!q) return true;
    const raw = f && typeof f === "object" ? f.raw : null;

    const hay = [
      f.id,
      f.findingid,
      f.title,
      f.pluginname,
      f.plugin_name,
      f.name,
      f.family,
      f.nvt_oid,
      f.nvtoid,
      f.cve_id,
      f.cveid,
      f.hostname,
      f.ip,
      f.port,
      f.port_num,
      f.proto,
      f.hostport,
      f.affected_asset,
      f.affectedAsset,
      f.asset_id,
      f.assetId,
      f.assetid,
      f.assetname,
      f.status,
      f.severity,
      f.threat,
      f.summary,
      f.description,
      f.solution,
      f.owner_team,
      f.department,

      raw?.ip,
      raw?.hostname,
      raw?.port,
      raw?.port_num,
      raw?.proto,
      raw?.nvtoid,
      raw?.name,
      raw?.family,
      raw?.cve,
      raw?.summary,
      raw?.description,
      raw?.solution,
    ]
      .map((x) => safeStr(x).toLowerCase())
      .join(" | ");

    return hay.includes(q);
  }

  function countBySeverity(findings) {
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    (findings || []).forEach((f) => {
      const s = lower(f.severity) || "info";
      if (s === "critical") out.critical++;
      else if (s === "high") out.high++;
      else if (s === "medium") out.medium++;
      else if (s === "low") out.low++;
      else out.info++;
    });
    return out;
  }

  // ===== BADGES (пилюли — theme-dark-shell.css) =====
  function renderSeverityBadge(sevRaw) {
    const sev = lower(sevRaw) || "info";
    const pill =
      sev === "critical"
        ? "findings-pill--sev-critical"
        : sev === "high"
          ? "findings-pill--sev-high"
          : sev === "medium"
            ? "findings-pill--sev-medium"
            : sev === "low"
              ? "findings-pill--sev-low"
              : "findings-pill--sev-info";
    return `<span class="findings-pill ${pill}">${escapeHtml(sevLabel(sev))}</span>`;
  }

  function normalizeStatusKey(f) {
    let key = String(f.status_key || lower(f.status) || "open").replace(/\s+/g, "_");
    const known = new Set([
      "open",
      "in_progress",
      "accepted_risk",
      "investigating",
      "resolved",
      "false_positive",
      "other",
    ]);
    if (!known.has(key)) key = "other";
    return key;
  }

  function renderStatusBadge(f) {
    const key = normalizeStatusKey(f);
    const text = statusLabelForFinding(f);
    const pill = `findings-pill--st-${key.replace(/_/g, "-")}`;
    return `<span class="findings-pill ${pill}">${escapeHtml(text)}</span>`;
  }

  function getSeverityCardClass(f) {
    const s = lower(f.severity) || "info";
    if (s === "critical") return "critical";
    if (s === "high") return "high";
    if (s === "medium") return "medium";
    if (s === "low") return "low";
    return "info";
  }

  function renderChips(counts, activeKey, totalBase) {
    const active = lower(activeKey);

    const items = [
      { key: "", label: RU.chips.all, count: totalBase, chip: "all" },
      { key: "critical", label: RU.chips.critical, count: counts.critical, chip: "critical" },
      { key: "high", label: RU.chips.high, count: counts.high, chip: "high" },
      { key: "medium", label: RU.chips.medium, count: counts.medium, chip: "medium" },
      { key: "low", label: RU.chips.low, count: counts.low, chip: "low" },
      { key: "info", label: RU.chips.info, count: counts.info, chip: "info" },
    ];

    return `
      <div class="findings-chips" role="toolbar" aria-label="Фильтр по критичности">
        ${items
          .map((x) => {
            const isActive = x.key ? active === x.key : !active;
            return `
              <button type="button" class="findings-chip findings-chip--${escapeHtml(x.chip)}${
                isActive ? " is-active" : ""
              }" data-sev="${escapeHtml(x.key)}">
                <span class="findings-chip__dot" aria-hidden="true"></span>
                <span>${escapeHtml(x.label)}</span>
                <span class="findings-chip__count">${Number(x.count || 0)}</span>
              </button>
            `;
          })
          .join("")}
      </div>
    `;
  }

  // ===== PAGINATION =====
  class PaginatedTable {
    constructor(options = {}) {
      this.currentPage = 1;
      this.itemsPerPage = options.itemsPerPage || 50;
      this.items = [];
      this.totalItems = 0;
    }
    setItems(items) {
      this.items = Array.isArray(items) ? items : [];
      this.totalItems = this.items.length;
      this.currentPage = 1;
    }
    getPage(pageNum) {
      const start = (pageNum - 1) * this.itemsPerPage;
      const end = start + this.itemsPerPage;
      return this.items.slice(start, end);
    }
    getTotalPages() {
      return Math.max(1, Math.ceil(this.totalItems / this.itemsPerPage));
    }
    nextPage() {
      const total = this.getTotalPages();
      if (this.currentPage < total) this.currentPage++;
    }
    prevPage() {
      if (this.currentPage > 1) this.currentPage--;
    }
    goToPage(pageNum) {
      const total = this.getTotalPages();
      const n = Number(pageNum);
      if (Number.isFinite(n) && n >= 1 && n <= total) this.currentPage = n;
    }
    renderPagination() {
      const total = this.getTotalPages();
      const current = this.currentPage;
      if (total <= 1) return "";

      const btnBase = "btn btn--outline btn--sm";
      const btnPrimary = "btn btn--primary btn--sm";
      const btnSecondary = "btn btn--secondary btn--sm";

      let nav =
        '<div class="findings-pagination"><div class="findings-pagination__nav">';

      nav += `<button class="${btnSecondary}" type="button"
        onclick="window._findingsPaginator.prevPage(); window._renderFindingsPage();"
        ${current <= 1 ? "disabled" : ""}>${RU.pagination.prev}</button>`;

      const maxVisible = 7;
      let startPage = Math.max(1, current - Math.floor(maxVisible / 2));
      let endPage = Math.min(total, startPage + maxVisible - 1);
      if (endPage - startPage < maxVisible - 1) startPage = Math.max(1, endPage - maxVisible + 1);

      if (startPage > 1) {
        nav += `<button class="${btnBase}" type="button"
          onclick="window._findingsPaginator.goToPage(1); window._renderFindingsPage();">1</button>`;
        if (startPage > 2)
          nav += `<span style="padding:6px 2px;color:var(--color-text-secondary);">…</span>`;
      }

      for (let i = startPage; i <= endPage; i++) {
        const isActive = i === current;
        nav += `<button class="${isActive ? btnPrimary : btnBase}" type="button"
          onclick="window._findingsPaginator.goToPage(${i}); window._renderFindingsPage();">${i}</button>`;
      }

      if (endPage < total) {
        if (endPage < total - 1)
          nav += `<span style="padding:6px 2px;color:var(--color-text-secondary);">…</span>`;
        nav += `<button class="${btnBase}" type="button"
          onclick="window._findingsPaginator.goToPage(${total}); window._renderFindingsPage();">${total}</button>`;
      }

      nav += `<button class="${btnSecondary}" type="button"
        onclick="window._findingsPaginator.nextPage(); window._renderFindingsPage();"
        ${current >= total ? "disabled" : ""}>${RU.pagination.next}</button>`;

      nav += `</div><div class="findings-pagination__meta">${escapeHtml(
        RU.pagination.page(current, total, this.totalItems)
      )}</div></div>`;
      return nav;
    }
  }

  // ===== MODAL =====
  function ensureFindingModal() {
    let overlay = document.getElementById("findingDetailsModal");
    if (overlay) return overlay;

    overlay = document.createElement("div");
    overlay.id = "findingDetailsModal";
    overlay.className = "modal-overlay";
    overlay.style.display = "none";
    overlay.style.overflow = "hidden"; // важно: не даём оверлею скроллиться

    overlay.innerHTML = `
      <div class="modal" style="width:min(980px, calc(100vw - 28px)); max-width:980px;">
        <div class="modal-title" style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <span id="fdmSevDot" style="width:10px;height:10px;border-radius:50%;background:#999;flex:0 0 auto;"></span>
            <div style="min-width:0;">
              <div id="fdmTitle" style="font-weight:1000;line-height:1.1;">${escapeHtml(
                RU.modal.title
              )}</div>
              <div id="fdmSubtitle" style="margin-top:4px;color:var(--color-text-secondary);font-size:12px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"></div>
            </div>
          </div>

          <div style="display:flex;gap:8px;align-items:center;">
            <button class="btn btn--outline btn--sm" type="button" id="fdmCopyBtn">${escapeHtml(
              RU.modal.copy
            )}</button>
            <button class="btn btn--secondary btn--sm" type="button" id="fdmCloseBtn">${escapeHtml(
              RU.modal.close
            )}</button>
          </div>
        </div>

        <div class="modal-text" style="padding-top: 12px;">
          <div id="fdmBody" style="max-height:min(70vh, 760px); overflow:auto;"></div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeFindingModal();
    });

    overlay.querySelector("#fdmCloseBtn")?.addEventListener("click", closeFindingModal);

    if (!window._findingModalEscBound) {
      window._findingModalEscBound = true;
      document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeFindingModal();
      });
    }

    return overlay;
  }

  function closeFindingModal() {
    const overlay = document.getElementById("findingDetailsModal");
    if (overlay) overlay.style.display = "none";
    window._lastFindingForCopy = null;
    lockBodyScroll(false);
  }

  function kvCard(label, valueHtml) {
    return `
      <div style="padding:10px 12px;border:1px solid rgba(255,255,255,.08);border-radius:12px;background:rgba(255,255,255,.02);">
        <div style="color:var(--color-text-secondary);font-size:12px;font-weight:900;">${escapeHtml(
          label
        )}</div>
        <div style="margin-top:6px;font-weight:900;color:var(--color-text);word-break:break-word;">${valueHtml}</div>
      </div>
    `;
  }

  function longBlock(title, text) {
    const t = safeStr(text).trim();
    return `
      <div style="margin-top:14px;">
        <div style="font-weight:1000;margin-bottom:8px;">${escapeHtml(title)}</div>
        <div style="
          border:1px solid rgba(255,255,255,.08);
          border-radius:14px;
          background:rgba(255,255,255,.02);
          padding:12px 12px;
          white-space:pre-wrap;
          line-height:1.45;
          color:var(--color-text);
        ">${escapeHtml(t || RU.modal.empty)}</div>
      </div>
    `;
  }

  function showFindingModal(f) {
    if (!f) return;

    const overlay = ensureFindingModal();
    const titleEl = overlay.querySelector("#fdmTitle");
    const subtitleEl = overlay.querySelector("#fdmSubtitle");
    const dotEl = overlay.querySelector("#fdmSevDot");
    const bodyEl = overlay.querySelector("#fdmBody");
    const copyBtn = overlay.querySelector("#fdmCopyBtn");

    const name = getFindingLabel(f);
    const host = getAssetLabel(f);

    const sev = lower(f.severity) || "info";
    const cvss = getCvss(f);

    const { portNum, proto } = getPortParts(f);
    const portDisplay = getPortDisplay(f);

    const family = safeStr(f.family || f.raw?.family || "").trim();
    const nvt = safeStr(
      f.nvt_oid || f.nvtoid || f.oid || f.raw?.nvtoid || f.raw?.nvt_oid || ""
    ).trim();
    const qod = safeStr(
      f.qodvalue || f.qod_value || f.qod || f.raw?.qodvalue || f.raw?.qod_value || ""
    ).trim();
    const threat = safeStr(f.threat || f.raw?.threat || "").trim();
    const detected = safeStr(
      f.detectedat || f.detected_at || f.createdat || f.created_at || f.raw?.detectedat || ""
    ).trim();

    const cves = extractCves(f);
    const summary = pickTextField(f, ["summary", "synopsis", "short_description"]);
    const description = pickTextField(f, ["description", "details", "detail", "long_description"]);
    const solution = pickTextField(f, ["solution", "recommendation", "fix", "remediation"]);

    if (titleEl) titleEl.textContent = name || RU.modal.title;
    if (subtitleEl) {
      subtitleEl.textContent = [host && host !== "-" ? host : "", portDisplay ? `порт ${portDisplay}` : ""]
        .filter(Boolean)
        .join(" · ");
    }
    if (dotEl) dotEl.style.background = COLORS[sev] || "#999";

    const mainGrid = `
      <div style="border:1px solid rgba(255,255,255,.08);border-radius:16px;background:rgba(255,255,255,.02);padding:12px;">
        <div style="display:grid;grid-template-columns:repeat(3, minmax(0, 1fr));gap:10px;">
          ${kvCard(RU.fields.severity, renderSeverityBadge(sev))}
          ${kvCard(RU.fields.status, renderStatusBadge(f))}
          ${kvCard(RU.fields.cvss, `<span style="font-size:18px;">${escapeHtml(cvss)}</span>`)}
        </div>

        <div style="margin-top:10px;display:grid;grid-template-columns:repeat(2, minmax(0, 1fr));gap:10px;">
          ${kvCard(RU.fields.host, `<span style="font-weight:1000;">${escapeHtml(host)}</span>`)}
          ${kvCard(RU.fields.port, escapeHtml(portDisplay || "—"))}
        </div>

        <div style="margin-top:10px;display:grid;grid-template-columns:repeat(3, minmax(0, 1fr));gap:10px;">
          ${kvCard(RU.fields.port_num, escapeHtml(portNum !== null ? String(portNum) : "—"))}
          ${kvCard(RU.fields.proto, escapeHtml(proto || "—"))}
          ${kvCard(RU.fields.qod, escapeHtml(qod || "—"))}
        </div>

        <div style="margin-top:10px;display:grid;grid-template-columns:repeat(3, minmax(0, 1fr));gap:10px;">
          ${kvCard(RU.fields.family, escapeHtml(family || "—"))}
          ${kvCard(RU.fields.nvt, escapeHtml(nvt || "—"))}
          ${kvCard(RU.fields.detected, escapeHtml(detected || "—"))}
        </div>

        <div style="margin-top:10px;display:grid;grid-template-columns:repeat(3, minmax(0, 1fr));gap:10px;">
          ${kvCard(
            RU.fields.cve,
            cves.length
              ? cves
                  .slice(0, 20)
                  .map(
                    (x) =>
                      `<span class="status status--info" style="margin-right:6px;display:inline-block;margin-bottom:6px;">${escapeHtml(
                        x
                      )}</span>`
                  )
                  .join("")
              : "—"
          )}
          ${kvCard(RU.fields.threat, escapeHtml(threat || "—"))}
          ${kvCard(RU.fields.name, escapeHtml(name || "—"))}
        </div>
      </div>
    `;

    const blocks = `
      ${longBlock(RU.modal.sectionSummary, summary)}
      ${longBlock(RU.modal.sectionDescription, description)}
      ${longBlock(RU.modal.sectionSolution, solution)}
      ${longBlock(RU.modal.sectionRaw, JSON.stringify(f, null, 2))}
    `;

    if (bodyEl) bodyEl.innerHTML = mainGrid + blocks;

    window._lastFindingForCopy = f;
    if (copyBtn && !copyBtn._bound) {
      copyBtn._bound = true;
      copyBtn.addEventListener("click", async () => {
        try {
          const obj = window._lastFindingForCopy;
          if (!obj) return;
          await navigator.clipboard.writeText(JSON.stringify(obj, null, 2));
          const old = copyBtn.textContent;
          copyBtn.textContent = RU.modal.copied;
          setTimeout(() => (copyBtn.textContent = old), 900);
        } catch (e) {
          console.error("Clipboard error:", e);
        }
      });
    }

    lockBodyScroll(true);
    overlay.style.display = "flex";
  }

  // ===== PAGE =====
  window.pages.findings = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">${RU.title}</div>
          <div class="card findings-layout" style="margin-top: 20px;">
            <div class="card-body" id="findingsContainer">${RU.summary.loading}</div>
          </div>
        </div>
      `;
    },

    async init() {
      try {
        if (!window.dataLoader) throw new Error("dataLoader is not loaded");
        if (!dataLoader.data && typeof dataLoader.loadDataset === "function") {
          await dataLoader.loadDataset();
        } else if (!dataLoader.data && typeof dataLoader.loadApplicationData === "function") {
          dataLoader.data = await dataLoader.loadApplicationData();
        }

        const data = dataLoader.data || {};
        let allFindings = Array.isArray(data.findings) ? data.findings : [];

        const container = document.getElementById("findingsContainer");
        if (!container) return;

        if (!allFindings.length) {
          container.innerHTML = `<div class="card__body">${RU.summary.noFindings}</div>`;
          return;
        }

        // sort by CVSS desc
        allFindings = allFindings.slice().sort((a, b) => {
          const cvssB = toNum(b.cvss_score || b.cvssbase || b.cvss_base || 0, 0);
          const cvssA = toNum(a.cvss_score || a.cvssbase || a.cvss_base || 0, 0);
          return cvssB - cvssA;
        });

        // stable row id
        allFindings = allFindings.map((f, i) => ({
          ...(f || {}),
          __rid: safeStr(f?.id || f?.findingid || "") || `rid-${i + 1}`,
        }));

        window._findingsByRid = new Map(allFindings.map((f) => [String(f.__rid), f]));

        const paginator = new PaginatedTable({ itemsPerPage: 50 });
        window._findingsPaginator = paginator;

        const hosts = uniqHosts(allFindings);
        const departments = uniqDepartments(allFindings);
        let selectedSeverity = "";

        container.innerHTML = `
          <div class="findings-page">
            <section class="findings-toolbar" aria-label="Фильтры">
              <div class="findings-toolbar__grid findings-toolbar__grid--5">
                <div>
                  <label class="form-label" for="findingsStatus">${RU.filters.status}</label>
                  <select class="form-control" id="findingsStatus">
                    <option value="">Все</option>
                    <option value="open">${RU.status.open}</option>
                    <option value="in_progress">${RU.status.in_progress}</option>
                    <option value="accepted_risk">${RU.status.accepted_risk}</option>
                    <option value="investigating">${RU.status.investigating}</option>
                    <option value="resolved">${RU.status.resolved}</option>
                    <option value="false_positive">${RU.status.false_positive}</option>
                    <option value="other">${RU.status.other}</option>
                  </select>
                </div>

                <div>
                  <label class="form-label" for="findingsDepartment">${RU.filters.department}</label>
                  <select class="form-control" id="findingsDepartment">
                    <option value="">Все</option>
                    ${departments.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join("")}
                  </select>
                </div>

                <div>
                  <label class="form-label" for="findingsHost">${RU.filters.host}</label>
                  <select class="form-control" id="findingsHost">
                    <option value="">Все</option>
                    ${hosts.map((h) => `<option value="${escapeHtml(h)}">${escapeHtml(h)}</option>`).join("")}
                  </select>
                </div>

                <div>
                  <label class="form-label" for="findingsSearch">${RU.filters.search}</label>
                  <input class="form-control" id="findingsSearch" placeholder="${escapeHtml(RU.placeholders.search)}" autocomplete="off" />
                </div>

                <div class="findings-toolbar__actions">
                  <button class="btn btn--secondary btn--sm" id="findingsResetBtn" type="button">${RU.filters.reset}</button>
                </div>
              </div>
              <div id="findingsChips"></div>
            </section>

            <section class="findings-main">
              <div id="findingsSummary" class="findings-summary"></div>
              <div id="findingsTableWrap" class="findings-list"></div>
              <div id="findingsPaginationWrap"></div>
            </section>
          </div>
        `;

        ensureFindingModal();

        const elStatus = document.getElementById("findingsStatus");
        const elDepartment = document.getElementById("findingsDepartment");
        const elHost = document.getElementById("findingsHost");
        const elSearch = document.getElementById("findingsSearch");
        const elReset = document.getElementById("findingsResetBtn");
        const elChips = document.getElementById("findingsChips");

        const elSummary = document.getElementById("findingsSummary");
        const elTableWrap = document.getElementById("findingsTableWrap");
        const elPaginationWrap = document.getElementById("findingsPaginationWrap");

        function getFilters() {
          return {
            severity: lower(selectedSeverity),
            status: lower(elStatus?.value),
            department: safeStr(elDepartment?.value).trim(),
            host: safeStr(elHost?.value).trim(),
            query: safeStr(elSearch?.value).trim().toLowerCase(),
          };
        }

        function renderTable() {
          const total = paginator.totalItems;
          const page = paginator.currentPage;
          const per = paginator.itemsPerPage;
          const start = total === 0 ? 0 : (page - 1) * per + 1;
          const end = Math.min(page * per, total);

          if (elSummary) {
            elSummary.textContent = total ? RU.summary.showing(start, end, total) : RU.summary.empty;
          }

          const pageItems = paginator.getPage(paginator.currentPage);

          if (!pageItems.length) {
            if (elTableWrap)
              elTableWrap.innerHTML = `<div class="findings-empty">${escapeHtml(RU.summary.empty)}</div>`;
            if (elPaginationWrap) elPaginationWrap.innerHTML = paginator.renderPagination();
            return;
          }

          const cards = pageItems
            .map((f) => {
              const cvss = getCvss(f);
              const assetName = getAssetLabel(f);
              const findingName = getFindingLabel(f);
              const sevClass = getSeverityCardClass(f);
              const port = getPortDisplay(f);
              const family = safeStr(f.family || f.raw?.family || "").trim();
              const metaTags = [];
              if (port) {
                metaTags.push(
                  `<span class="findings-card__meta-tag findings-card__meta-tag--accent">${escapeHtml(port)}</span>`
                );
              }
              if (family) {
                metaTags.push(`<span class="findings-card__meta-tag">${escapeHtml(family)}</span>`);
              }
              const metaHtml = metaTags.length
                ? `<div class="findings-card__meta">${metaTags.join("")}</div>`
                : "";
              return `
              <article class="findings-card findings-card--${sevClass}" data-rid="${escapeHtml(
                String(f.__rid)
              )}" tabindex="0" role="button" aria-label="Подробнее: ${escapeHtml(findingName)}">
                <div class="findings-card__host">${escapeHtml(assetName)}</div>
                <div class="findings-card__cvss">
                  <span class="findings-card__cvss-val">${escapeHtml(cvss)}</span>
                  <span class="findings-card__cvss-label">${escapeHtml(RU.table.cvss)}</span>
                </div>
                <p class="findings-card__title">${escapeHtml(findingName)}</p>
                ${metaHtml}
                <div class="findings-card__badges">
                  ${renderSeverityBadge(f.severity)}
                  ${renderStatusBadge(f)}
                </div>
              </article>`;
            })
            .join("");

          if (elTableWrap) elTableWrap.innerHTML = cards;
          if (elPaginationWrap) elPaginationWrap.innerHTML = paginator.renderPagination();
        }

        function applyFilters({ resetPage } = { resetPage: true }) {
          const { severity, status, department, host, query } = getFilters();

          // base = status/host/search; severity применяем отдельно (чтобы чипы считались корректно)
          let base = allFindings;

          if (status) {
            base = base.filter((f) => {
              const key = f.status_key || lower(f.status);
              return key === status;
            });
          }

          if (department) {
            base = base.filter((f) => safeStr(f.owner_team || f.department).trim() === department);
          }

          if (host) {
            base = base.filter((f) => getAssetLabel(f) === host);
          }

          if (query) {
            base = base.filter((f) => matchesQuery(f, query));
          }

          const counts = countBySeverity(base);
          if (elChips) elChips.innerHTML = renderChips(counts, severity, base.length);

          let out = base;
          if (severity) out = out.filter((f) => lower(f.severity) === severity);

          const prevPage = paginator.currentPage;
          paginator.setItems(out);

          if (!resetPage) paginator.currentPage = Math.min(prevPage, paginator.getTotalPages());

          renderTable();
        }

        // pagination callback
        window._renderFindingsPage = function () {
          applyFilters({ resetPage: false });
        };

        if (elTableWrap && !elTableWrap._rowClickBound) {
          elTableWrap._rowClickBound = true;
          elTableWrap.addEventListener("click", (e) => {
            const card = e.target?.closest?.(".findings-card[data-rid]");
            if (!card) return;
            const rid = card.getAttribute("data-rid");
            const f = window._findingsByRid?.get(String(rid));
            if (f) showFindingModal(f);
          });
          elTableWrap.addEventListener("keydown", (e) => {
            if (e.key !== "Enter" && e.key !== " ") return;
            const card = e.target?.closest?.(".findings-card[data-rid]");
            if (!card) return;
            e.preventDefault();
            const rid = card.getAttribute("data-rid");
            const f = window._findingsByRid?.get(String(rid));
            if (f) showFindingModal(f);
          });
        }

        // events
        elStatus?.addEventListener("change", () => applyFilters({ resetPage: true }));
        elDepartment?.addEventListener("change", () => applyFilters({ resetPage: true }));
        elHost?.addEventListener("change", () => applyFilters({ resetPage: true }));

        elChips?.addEventListener("click", (e) => {
          const btn = e.target?.closest?.("button[data-sev]");
          if (!btn) return;
          selectedSeverity = safeStr(btn.getAttribute("data-sev"));
          applyFilters({ resetPage: true });
        });

        // search debounce
        let tmr = null;
        elSearch?.addEventListener("input", () => {
          clearTimeout(tmr);
          tmr = setTimeout(() => applyFilters({ resetPage: true }), 180);
        });

        // reset
        elReset?.addEventListener("click", () => {
          selectedSeverity = "";
          if (elStatus) elStatus.value = "";
          if (elDepartment) elDepartment.value = "";
          if (elHost) elHost.value = "";
          if (elSearch) elSearch.value = "";
          applyFilters({ resetPage: true });
        });

        try {
          const prefRaw = sessionStorage.getItem("vm_findings_prefilter");
          if (prefRaw) {
            const pref = JSON.parse(prefRaw);
            sessionStorage.removeItem("vm_findings_prefilter");
            const h = safeStr(pref.host).trim();
            if (h && elHost && Array.from(elHost.options).some((o) => o.value === h)) elHost.value = h;
            const dep = safeStr(pref.department).trim();
            if (dep && elDepartment && Array.from(elDepartment.options).some((o) => o.value === dep))
              elDepartment.value = dep;
          }
        } catch (_) {}

        // initial
        paginator.setItems(allFindings);
        applyFilters({ resetPage: true });
      } catch (err) {
        console.error("❌ Findings init error:", err);
        const container = document.getElementById("findingsContainer");
        if (container) {
          container.innerHTML = `<div class="card__body" style="color: var(--color-error);">Ошибка: ${escapeHtml(
            err.message
          )}</div>`;
        }
      }
    },
  };
})();
