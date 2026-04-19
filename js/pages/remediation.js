// js/pages/remediation.js — контроль устранения (сроки п. 6.4, исполнитель, статус)
(() => {
  "use strict";
  window.pages = window.pages || {};

  const LS_KEY = "vm_remediation_control_v1";

  const REM_STATUS_OPTS = [
    { key: "rem_open", label: "Ожидает устранения" },
    { key: "rem_assigned", label: "Назначено" },
    { key: "rem_in_progress", label: "В работе" },
    { key: "rem_verified", label: "На приёмке" },
    { key: "rem_done", label: "Устранено (контроль)" },
  ];

  function readStore() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      const o = raw ? JSON.parse(raw) : {};
      return o && typeof o === "object" ? o : {};
    } catch (_) {
      return {};
    }
  }

  function writeStore(o) {
    try {
      localStorage.setItem(LS_KEY, JSON.stringify(o));
    } catch (_) {}
  }

  window.vmRemediationStore = {
    getAssignee(rid) {
      const o = readStore();
      const v = o.assignees && o.assignees[rid];
      return v === null || v === undefined ? "" : String(v).trim();
    },
    setAssignee(rid, value) {
      const o = readStore();
      o.assignees = o.assignees || {};
      o.assignees[rid] = String(value || "").trim();
      writeStore(o);
    },
    getCtlStatus(rid) {
      const o = readStore();
      const v = o.ctlStatus && o.ctlStatus[rid];
      const s = String(v || "").trim();
      const allowed = new Set(REM_STATUS_OPTS.map((x) => x.key));
      return allowed.has(s) ? s : "rem_open";
    },
    setCtlStatus(rid, value) {
      const o = readStore();
      o.ctlStatus = o.ctlStatus || {};
      const allowed = new Set(REM_STATUS_OPTS.map((x) => x.key));
      o.ctlStatus[rid] = allowed.has(value) ? value : "rem_open";
      writeStore(o);
    },
    getAssigneeSuggestions() {
      const o = readStore();
      const set = new Set(["Не назначен", "Системный администратор", "Отдел ИБ", "ИБ-офицер"]);
      Object.values(o.assignees || {}).forEach((x) => {
        const s = String(x || "").trim();
        if (s) set.add(s);
      });
      return Array.from(set).sort((a, b) => a.localeCompare(b, "ru")).slice(0, 60);
    },
  };

  const RU = {
    title: "Контроль устранения",
    filters: {
      status: "Статус (сканер)",
      department: "Подразделение",
      host: "Хост",
      search: "Поиск",
      reset: "Сбросить",
    },
    placeholders: { search: "CVE, плагин, порт, хост…" },
    summary: {
      showing: (a, b, t) => `Показаны ${a}–${b} из ${t}`,
      empty: "По выбранным фильтрам ничего не найдено",
      loading: "Загрузка…",
      noFindings: "Уязвимости не найдены",
    },
    table: { cvss: "CVSS" },
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
    fields: {
      deadline: "Крайний срок устранения",
      ctl: "Статус устранения",
      assignee: "Исполнитель",
    },
    noDetected: "Дата обнаружения не задана — срок не вычислен",
    overdue: "Просрочено",
    dueSoon: "Скоро истекает",
  };

  const COLORS = {
    critical: "#F44336",
    high: "#FF9800",
    medium: "#FFC107",
    low: "#4CAF50",
    info: "#2196F3",
    all: "rgba(255,255,255,.55)",
  };

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

  function sevLabel(sev) {
    const s = lower(sev) || "info";
    return RU.severity[s] || RU.severity.info;
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
      f.title,
      f.pluginname,
      f.plugin_name,
      f.name,
      f.family,
      f.nvt_oid,
      f.hostname,
      f.ip,
      f.port,
      f.affected_asset,
      f.asset_id,
      f.status,
      f.severity,
      f.owner_team,
      f.department,
      raw?.ip,
      raw?.hostname,
      raw?.cve,
      raw?.name,
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

  function remediationCtlDeadlineClass(f, rid) {
    const dueFn = window.vmGetRemediationDueMs;
    const due = typeof dueFn === "function" ? dueFn(f) : null;
    if (due === null) return "";
    if (window.vmRemediationStore.getCtlStatus(rid) === "rem_done") return "";
    const now = Date.now();
    if (now > due) return "findings-card__deadline--over";
    if (due - now < 72 * 60 * 60 * 1000) return "findings-card__deadline--warn";
    return "";
  }

  function remediationCardDeadlineHtml(f, rid) {
    const dueFn = window.vmGetRemediationDueMs;
    const fmt = window.vmFormatRuDateTimeMs;
    const due = typeof dueFn === "function" ? dueFn(f) : null;
    const vis = remediationCtlDeadlineClass(f, rid);
    if (due === null) {
      return `<div class="findings-card__deadline ${escapeHtml(vis)}"><span>${escapeHtml(
        RU.fields.deadline
      )}: </span><strong>${escapeHtml(RU.noDetected)}</strong></div>`;
    }
    const label = typeof fmt === "function" ? fmt(due) : "—";
    const extra =
      vis === "findings-card__deadline--over"
        ? ` · ${escapeHtml(RU.overdue)}`
        : vis === "findings-card__deadline--warn"
          ? ` · ${escapeHtml(RU.dueSoon)}`
          : "";
    return `<div class="findings-card__deadline ${escapeHtml(vis)}"><span>${escapeHtml(
      RU.fields.deadline
    )}: </span><strong>${escapeHtml(label)}</strong>${extra}</div>`;
  }

  function safeHtmlIdPart(rid) {
    return safeStr(rid).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 120) || "x";
  }

  function renderCtlSelect(rid, current) {
    const rAttr = escapeHtml(rid);
    const idSafe = escapeHtml(safeHtmlIdPart(rid));
    const cur = REM_STATUS_OPTS.some((o) => o.key === current) ? current : "rem_open";
    return `<select class="form-control" id="rem-ctl-${idSafe}" data-vm-card="ctl" data-rid="${rAttr}">
      ${REM_STATUS_OPTS.map(
        (o) =>
          `<option value="${escapeHtml(o.key)}"${o.key === cur ? " selected" : ""}>${escapeHtml(
            o.label
          )}</option>`
      ).join("")}
    </select>`;
  }

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
      return this.items.slice(start, start + this.itemsPerPage);
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
        onclick="window._remediationPaginator.prevPage(); window._renderRemediationPage();"
        ${current <= 1 ? "disabled" : ""}>${RU.pagination.prev}</button>`;
      const maxVisible = 7;
      let startPage = Math.max(1, current - Math.floor(maxVisible / 2));
      let endPage = Math.min(total, startPage + maxVisible - 1);
      if (endPage - startPage < maxVisible - 1) startPage = Math.max(1, endPage - maxVisible + 1);
      if (startPage > 1) {
        nav += `<button class="${btnBase}" type="button"
          onclick="window._remediationPaginator.goToPage(1); window._renderRemediationPage();">1</button>`;
        if (startPage > 2)
          nav += `<span style="padding:6px 2px;color:var(--color-text-secondary);">…</span>`;
      }
      for (let i = startPage; i <= endPage; i++) {
        const isActive = i === current;
        nav += `<button class="${isActive ? btnPrimary : btnBase}" type="button"
          onclick="window._remediationPaginator.goToPage(${i}); window._renderRemediationPage();">${i}</button>`;
      }
      if (endPage < total) {
        if (endPage < total - 1)
          nav += `<span style="padding:6px 2px;color:var(--color-text-secondary);">…</span>`;
        nav += `<button class="${btnBase}" type="button"
          onclick="window._remediationPaginator.goToPage(${total}); window._renderRemediationPage();">${total}</button>`;
      }
      nav += `<button class="${btnSecondary}" type="button"
        onclick="window._remediationPaginator.nextPage(); window._renderRemediationPage();"
        ${current >= total ? "disabled" : ""}>${RU.pagination.next}</button>`;
      nav += `</div><div class="findings-pagination__meta">${escapeHtml(
        RU.pagination.page(current, total, this.totalItems)
      )}</div></div>`;
      return nav;
    }
  }

  window.pages.remediation = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">${RU.title}</div>
          <div class="card findings-layout" style="margin-top: 20px;">
            <div class="card-body" id="remediationContainer">${RU.summary.loading}</div>
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
        const container = document.getElementById("remediationContainer");
        if (!container) return;

        if (!allFindings.length) {
          container.innerHTML = `<div class="card__body">${RU.summary.noFindings}</div>`;
          return;
        }

        allFindings = allFindings.slice().sort((a, b) => {
          const cvssB = toNum(b.cvss_score || b.cvssbase || b.cvss_base || 0, 0);
          const cvssA = toNum(a.cvss_score || a.cvssbase || a.cvss_base || 0, 0);
          return cvssB - cvssA;
        });

        allFindings = allFindings.map((f, i) => ({
          ...(f || {}),
          __rid: safeStr(f?.id || f?.findingid || "") || `rid-${i + 1}`,
        }));

        window._remediationByRid = new Map(allFindings.map((f) => [String(f.__rid), f]));

        const paginator = new PaginatedTable({ itemsPerPage: 50 });
        window._remediationPaginator = paginator;

        const hosts = uniqHosts(allFindings);
        const departments = uniqDepartments(allFindings);
        let selectedSeverity = "";

        const sugg = window.vmRemediationStore.getAssigneeSuggestions();
        const datalistHtml = `<datalist id="vmRemExecutorsPage">${sugg
          .map((x) => `<option value="${escapeHtml(x)}"></option>`)
          .join("")}</datalist>`;

        container.innerHTML = `
          <div class="findings-page">
            ${datalistHtml}
            <section class="findings-toolbar" aria-label="Фильтры">
              <div class="findings-toolbar__grid findings-toolbar__grid--5">
                <div>
                  <label class="form-label" for="remediationStatus">${RU.filters.status}</label>
                  <select class="form-control" id="remediationStatus">
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
                  <label class="form-label" for="remediationDepartment">${RU.filters.department}</label>
                  <select class="form-control" id="remediationDepartment">
                    <option value="">Все</option>
                    ${departments.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join("")}
                  </select>
                </div>
                <div>
                  <label class="form-label" for="remediationHost">${RU.filters.host}</label>
                  <select class="form-control" id="remediationHost">
                    <option value="">Все</option>
                    ${hosts.map((h) => `<option value="${escapeHtml(h)}">${escapeHtml(h)}</option>`).join("")}
                  </select>
                </div>
                <div>
                  <label class="form-label" for="remediationSearch">${RU.filters.search}</label>
                  <input class="form-control" id="remediationSearch" placeholder="${escapeHtml(
                    RU.placeholders.search
                  )}" autocomplete="off" />
                </div>
                <div class="findings-toolbar__actions">
                  <button class="btn btn--secondary btn--sm" id="remediationResetBtn" type="button">${RU.filters.reset}</button>
                </div>
              </div>
              <div id="remediationChips"></div>
            </section>

            <section class="findings-main">
              <div id="remediationSummary" class="findings-summary"></div>
              <div id="remediationTableWrap" class="findings-list"></div>
              <div id="remediationPaginationWrap"></div>
            </section>
          </div>
        `;

        const elStatus = document.getElementById("remediationStatus");
        const elDepartment = document.getElementById("remediationDepartment");
        const elHost = document.getElementById("remediationHost");
        const elSearch = document.getElementById("remediationSearch");
        const elReset = document.getElementById("remediationResetBtn");
        const elChips = document.getElementById("remediationChips");
        const elSummary = document.getElementById("remediationSummary");
        const elTableWrap = document.getElementById("remediationTableWrap");
        const elPaginationWrap = document.getElementById("remediationPaginationWrap");

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
              const rid = String(f.__rid);
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
              const deadlineRow = remediationCardDeadlineHtml(f, rid);
              const assigneeVal = window.vmRemediationStore.getAssignee(rid);
              const ctlCur = window.vmRemediationStore.getCtlStatus(rid);
              const ridAttr = escapeHtml(rid);
              const idPart = escapeHtml(safeHtmlIdPart(rid));
              return `
              <article class="findings-card findings-card--${sevClass} findings-card--with-rem-controls" data-rid="${ridAttr}" tabindex="0" role="button" aria-label="Подробнее: ${escapeHtml(
                findingName
              )}">
                <div class="findings-card__host">${escapeHtml(assetName)}</div>
                <div class="findings-card__cvss">
                  <span class="findings-card__cvss-val">${escapeHtml(cvss)}</span>
                  <span class="findings-card__cvss-label">${escapeHtml(RU.table.cvss)}</span>
                </div>
                <p class="findings-card__title">${escapeHtml(findingName)}</p>
                ${metaHtml}
                ${deadlineRow}
                <div class="findings-card__remctl">
                  <div>
                    <label class="form-label" for="rem-ctl-${idPart}">${escapeHtml(RU.fields.ctl)}</label>
                    ${renderCtlSelect(rid, ctlCur)}
                  </div>
                  <div>
                    <label class="form-label" for="rem-as-${idPart}">${escapeHtml(RU.fields.assignee)}</label>
                    <input class="form-control" id="rem-as-${idPart}" type="text" data-vm-card="assignee" data-rid="${ridAttr}"
                      list="vmRemExecutorsPage" autocomplete="off" value="${escapeHtml(assigneeVal)}" />
                  </div>
                </div>
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

        window._renderRemediationPage = function () {
          applyFilters({ resetPage: false });
        };

        window._vmRemediationRefresh = function () {
          applyFilters({ resetPage: false });
        };

        if (elTableWrap && !elTableWrap._remediationBound) {
          elTableWrap._remediationBound = true;

          elTableWrap.addEventListener("click", (e) => {
            if (e.target?.closest?.("select, input, button, textarea, label")) return;
            const card = e.target?.closest?.(".findings-card[data-rid]");
            if (!card) return;
            const rid = card.getAttribute("data-rid");
            const f = window._remediationByRid?.get(String(rid));
            if (f && typeof window.vmShowFindingModal === "function") {
              window.vmShowFindingModal({ ...f, _vmRemediationUi: true });
            }
          });

          elTableWrap.addEventListener("keydown", (e) => {
            if (e.key !== "Enter" && e.key !== " ") return;
            if (e.target?.closest?.("select, input, textarea")) return;
            const card = e.target?.closest?.(".findings-card[data-rid]");
            if (!card) return;
            e.preventDefault();
            const rid = card.getAttribute("data-rid");
            const f = window._remediationByRid?.get(String(rid));
            if (f && typeof window.vmShowFindingModal === "function") {
              window.vmShowFindingModal({ ...f, _vmRemediationUi: true });
            }
          });

          elTableWrap.addEventListener("change", (e) => {
            const t = e.target;
            if (!(t instanceof HTMLSelectElement)) return;
            if (!t.matches?.('[data-vm-card="ctl"]')) return;
            const rid = safeStr(t.getAttribute("data-rid"));
            if (!rid) return;
            window.vmRemediationStore.setCtlStatus(rid, t.value);
            applyFilters({ resetPage: false });
          });

          let assignT = null;
          elTableWrap.addEventListener("input", (e) => {
            const t = e.target;
            if (!(t instanceof HTMLInputElement)) return;
            if (!t.matches?.('[data-vm-card="assignee"]')) return;
            const rid = safeStr(t.getAttribute("data-rid"));
            if (!rid) return;
            clearTimeout(assignT);
            assignT = setTimeout(() => {
              window.vmRemediationStore.setAssignee(rid, t.value);
            }, 300);
          });
        }

        elStatus?.addEventListener("change", () => applyFilters({ resetPage: true }));
        elDepartment?.addEventListener("change", () => applyFilters({ resetPage: true }));
        elHost?.addEventListener("change", () => applyFilters({ resetPage: true }));

        elChips?.addEventListener("click", (e) => {
          const btn = e.target?.closest?.("button[data-sev]");
          if (!btn) return;
          selectedSeverity = safeStr(btn.getAttribute("data-sev"));
          applyFilters({ resetPage: true });
        });

        let tmr = null;
        elSearch?.addEventListener("input", () => {
          clearTimeout(tmr);
          tmr = setTimeout(() => applyFilters({ resetPage: true }), 180);
        });

        elReset?.addEventListener("click", () => {
          selectedSeverity = "";
          if (elStatus) elStatus.value = "";
          if (elDepartment) elDepartment.value = "";
          if (elHost) elHost.value = "";
          if (elSearch) elSearch.value = "";
          applyFilters({ resetPage: true });
        });

        paginator.setItems(allFindings);
        applyFilters({ resetPage: true });
      } catch (err) {
        console.error("Remediation init error:", err);
        const c = document.getElementById("remediationContainer");
        if (c) {
          c.innerHTML = `<div class="card__body" style="color: var(--color-error);">Ошибка: ${escapeHtml(
            err.message
          )}</div>`;
        }
      }
    },
  };
})();
