// js/pages/assets.js
(() => {
  "use strict";
  window.pages = window.pages || {};

  const RU = {
    title: "Активы",
    search: "Быстрый поиск по имени или IP…",
    cols: {
      name: "Имя",
      ip: "IP-адрес",
      risk: "Риск (скан)",
      findings: "Уязвимости",
      ports: "Порты",
      type: "Тип",
      zone: "Зона",
      team: "Команда",
    },
    modal: {
      title: "Карточка актива",
      close: "Закрыть",
      maxCvss: "Макс. CVSS (активные)",
      businessCrit: "Критичность (учёт)",
      open: "Открыто",
      total: "Всего записей",
      ports: "Открытые порты",
      portsHint: "Собрано из результатов сканирования по сервисам.",
      severity: "Распределение по критичности (активные)",
      findingsList: "Уязвимости хоста",
      lastSeen: "Последнее обнаружение",
      none: "—",
    },
    risk: {
      critical: "Критический",
      high: "Высокий",
      medium: "Средний",
      low: "Низкий",
      info: "Инфо",
      none: "Нет данных",
    },
    crit: {
      unset: "Не задана",
      v5: "Критическая",
      v4: "Высокая",
      v3: "Средняя",
      v2: "Низкая",
      v1: "Минимальная",
    },
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
  function toNum(v, fb = 0) {
    const n = Number(v);
    return Number.isFinite(n) ? n : fb;
  }
  function uniq(arr) {
    return Array.from(new Set((arr || []).filter(Boolean)));
  }

  async function ensureData() {
    if (!window.dataLoader) throw new Error("dataLoader is not loaded");
    if (!dataLoader.data) {
      if (typeof dataLoader.loadDataset === "function") await dataLoader.loadDataset();
      else if (typeof dataLoader.loadApplicationData === "function")
        dataLoader.data = await dataLoader.loadApplicationData();
    }
    return dataLoader.data;
  }

  function ipToNum(ip) {
    const s = safeStr(ip).trim();
    const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const a = m.slice(1).map((x) => Number(x));
    if (a.some((x) => !Number.isFinite(x) || x < 0 || x > 255)) return null;
    return (((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]) >>> 0);
  }

  function normalizeRow(a) {
    const id = safeStr(a.id || a.asset_id);
    const name = safeStr(a.name || a.hostname || a.ip_address || id);
    const ip = safeStr(a.ip_address || a.ip || "");
    return {
      raw: a,
      id: id || name,
      name,
      hostname: safeStr(a.hostname || ""),
      ip,
      type: safeStr(a.asset_type || a.type || ""),
      zone: safeStr(a.network_zone || a.zone || ""),
      team: safeStr(a.owner_team || a.team || ""),
      criticality: a.criticality_num,
      status: safeStr(a.status || ""),
    };
  }

  function findingBelongs(f, row) {
    const aid = safeStr(row.id);
    if (aid && safeStr(f.asset_id) === aid) return true;
    const nm = lower(row.name);
    if (nm && (lower(f.affected_asset) === nm || lower(f.hostname) === nm)) return true;
    const ip = safeStr(row.ip);
    if (ip && safeStr(f.ip) === ip) return true;
    return false;
  }

  function portKey(f) {
    const r = f.raw || {};
    const p = safeStr(r.port || r.hostport || f.port || "").trim();
    if (p) return p;
    const n = r.port_num ?? r.portnum ?? f.port_num;
    const pr = safeStr(r.proto || r.protocol || "").trim();
    if (n != null && n !== "" && Number.isFinite(Number(n))) {
      return pr ? `${n}/${pr}` : String(n);
    }
    return "";
  }

  function computeContext(row, allFindings) {
    const related = allFindings.filter((f) => findingBelongs(f, row));
    const active = related.filter((f) => {
      const k = f.status_key || "";
      return k !== "resolved" && k !== "false_positive";
    });
    const sevRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    let maxCvss = 0;
    let maxSev = "info";
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    active.forEach((f) => {
      const cv = toNum(f.cvss_score ?? f.cvssbase, 0);
      if (cv > maxCvss) maxCvss = cv;
      const s = lower(f.severity) || "info";
      if (counts[s] !== undefined) counts[s]++;
      else counts.info++;
      if ((sevRank[s] || 0) > (sevRank[maxSev] || 0)) maxSev = s;
    });
    const ports = uniq(related.map(portKey).filter(Boolean)).sort((a, b) =>
      a.localeCompare(b, "ru", { numeric: true })
    );
    const openCount = related.filter((f) => f.status_key === "open").length;
    let lastDet = "";
    related.forEach((f) => {
      const d = safeStr(f.detectedat || f.raw?.detected_at || "");
      if (d && (!lastDet || d > lastDet)) lastDet = d;
    });
    const totalActive = active.length;
    return {
      related,
      active,
      maxCvss,
      maxSev,
      counts,
      ports,
      openCount,
      total: related.length,
      totalActive,
      lastDetected: lastDet,
    };
  }

  function getCvssFinding(f) {
    return toNum(f.cvss_score ?? f.cvssbase ?? f.cvss_base, 0).toFixed(1);
  }

  function getFindingTitle(f) {
    return (
      safeStr(f.title || f.name || f.pluginname || f.plugin_name || f.nvt_oid || "—").trim() || "—"
    );
  }

  function getPortDisplayFinding(f) {
    const r = f.raw || {};
    const portStr = safeStr(f.port || r.port || r.hostport || "").trim();
    if (portStr) return portStr;
    const n = r.port_num ?? r.portnum ?? f.port_num;
    const pr = safeStr(r.proto || r.protocol || "").trim();
    if (n != null && n !== "" && Number.isFinite(Number(n))) return pr ? `${n}/${pr}` : String(n);
    return "";
  }

  function getSeverityCardClass(f) {
    const s = lower(f.severity) || "info";
    if (s === "critical") return "critical";
    if (s === "high") return "high";
    if (s === "medium") return "medium";
    if (s === "low") return "low";
    return "info";
  }

  function normalizeStatusKeyForPill(f) {
    const wf = window.vmFindingWorkflowStore;
    if (wf) return wf.getStatusForFinding(f);
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

  function statusLabelFinding(f) {
    const key = normalizeStatusKeyForPill(f);
    const map = {
      open: "Открыто",
      in_progress: "В работе",
      accepted_risk: "Риск принят",
      investigating: "Расследование",
      resolved: "Устранено",
      false_positive: "Ложноположительное",
      other: "Прочее",
    };
    if (map[key]) return map[key];
    return safeStr(f.status_display || f.status || key);
  }

  function renderFindingCardsForModal(row, findingsSorted) {
    if (!findingsSorted.length) {
      return `<p class="asset-modal__findings-empty">Нет находок по этому хосту.</p>`;
    }
    return findingsSorted
      .map((f) => {
        const cvss = getCvssFinding(f);
        const title = getFindingTitle(f);
        const sevClass = getSeverityCardClass(f);
        const port = getPortDisplayFinding(f);
        const family = safeStr(f.family || f.raw?.family || "").trim();
        const sk = lower(f.severity) || "info";
        const sevPill =
          sk === "critical"
            ? "findings-pill--sev-critical"
            : sk === "high"
              ? "findings-pill--sev-high"
              : sk === "medium"
                ? "findings-pill--sev-medium"
                : sk === "low"
                  ? "findings-pill--sev-low"
                  : "findings-pill--sev-info";
        const stKey = normalizeStatusKeyForPill(f);
        const stPill = `findings-pill--st-${stKey.replace(/_/g, "-")}`;
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
        const deadlineHtml =
          typeof window.vmRemediationDeadlineHtml === "function"
            ? window.vmRemediationDeadlineHtml(f)
            : "";
        return `
      <article class="findings-card findings-card--${sevClass} asset-modal-finding-card">
        <div class="findings-card__host">${escapeHtml(row.name)}</div>
        <div class="findings-card__cvss">
          <span class="findings-card__cvss-val">${escapeHtml(cvss)}</span>
          <span class="findings-card__cvss-label">CVSS</span>
        </div>
        <p class="findings-card__title">${escapeHtml(title)}</p>
        ${metaHtml}
        ${deadlineHtml}
        <div class="findings-card__badges">
          <span class="findings-pill ${sevPill}">${escapeHtml(RU.risk[sk] || RU.risk.info)}</span>
          <span class="findings-pill ${stPill}">${escapeHtml(statusLabelFinding(f))}</span>
        </div>
      </article>`;
      })
      .join("");
  }

  function riskPillClass(sev) {
    const s = lower(sev) || "info";
    if (s === "critical") return "assets-risk-pill--critical";
    if (s === "high") return "assets-risk-pill--high";
    if (s === "medium") return "assets-risk-pill--medium";
    if (s === "low") return "assets-risk-pill--low";
    if (s === "info") return "assets-risk-pill--info";
    return "assets-risk-pill--none";
  }

  function riskLabel(sev, empty) {
    if (empty) return RU.risk.none;
    const s = lower(sev) || "info";
    return RU.risk[s] || RU.risk.info;
  }

  function criticalityMeta(n) {
    if (n == null || !Number.isFinite(Number(n))) {
      return { label: RU.crit.unset, cls: "assets-risk-pill--none" };
    }
    const v = Number(n);
    if (v >= 5) return { label: RU.crit.v5, cls: "assets-risk-pill--critical" };
    if (v >= 4) return { label: RU.crit.v4, cls: "assets-risk-pill--high" };
    if (v >= 3) return { label: RU.crit.v3, cls: "assets-risk-pill--medium" };
    if (v >= 2) return { label: RU.crit.v2, cls: "assets-risk-pill--low" };
    return { label: RU.crit.v1, cls: "assets-risk-pill--info" };
  }

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

  function ensureAssetModal() {
    let el = document.getElementById("assetDetailModal");
    if (el) {
      el.querySelector(".asset-modal__footer")?.remove();
      return el;
    }
    el = document.createElement("div");
    el.id = "assetDetailModal";
    el.className = "modal-overlay";
    el.style.display = "none";
    el.innerHTML = `
      <div class="modal asset-modal__dialog">
        <div class="modal-title asset-modal__header" style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
          <span>${escapeHtml(RU.modal.title)}</span>
          <button type="button" class="btn btn--secondary btn--sm" id="assetModalClose">${escapeHtml(
            RU.modal.close
          )}</button>
        </div>
        <div id="assetModalBody" class="asset-modal__body"></div>
      </div>`;
    document.body.appendChild(el);
    el.addEventListener("click", (e) => {
      if (e.target === el) closeAssetModal();
    });
    el.querySelector("#assetModalClose")?.addEventListener("click", closeAssetModal);
    return el;
  }

  function closeAssetModal() {
    const el = document.getElementById("assetDetailModal");
    if (el) el.style.display = "none";
    window._assetModalContext = null;
    lockBodyScroll(false);
  }

  const ASSET_SEV_COLORS = {
    critical: "#f07178",
    high: "#ffab70",
    medium: "#e7c66f",
    low: "#7fd99a",
    info: "#7eb8ff",
  };

  const ASSET_SEV_LABEL = {
    critical: "Критический",
    high: "Высокий",
    medium: "Средний",
    low: "Низкий",
    info: "Инфо",
  };

  function wireAssetSeverityBar(ctx) {
    const bar = document.getElementById("assetSevBar");
    if (!bar || !window.vmTooltip) return;

    const segs = bar.querySelectorAll(".asset-bar-seg");
    if (!segs.length) return;

    const sum =
      ctx.counts.critical +
      ctx.counts.high +
      ctx.counts.medium +
      ctx.counts.low +
      ctx.counts.info;

    function dim(activeEl) {
      segs.forEach((el) => {
        if (!activeEl) {
          el.style.opacity = "1";
          el.style.filter = "none";
        } else if (el === activeEl) {
          el.style.opacity = "1";
          el.style.filter = "drop-shadow(0 0 10px rgba(255,255,255,.14))";
        } else {
          el.style.opacity = "0.28";
          el.style.filter = "none";
        }
      });
    }

    segs.forEach((el) => {
      el.addEventListener("mouseenter", () => dim(el));
      el.addEventListener("mouseleave", () => {
        dim(null);
        window.vmTooltip.hide();
      });
      el.addEventListener("mousemove", (ev) => {
        const k = safeStr(el.getAttribute("data-sev"));
        const val = Number(el.getAttribute("data-val") || 0);
        const total = Number(el.getAttribute("data-total") || sum);
        window.vmTooltip.showAt({
          x: ev.clientX,
          y: ev.clientY,
          title: ASSET_SEV_LABEL[k] || k,
          value: val,
          percent: window.vmTooltip.pct(val, total),
          color: ASSET_SEV_COLORS[k] || "#999",
          subtitle: "уязвимостей",
        });
      });
    });

    bar.addEventListener("mouseleave", () => {
      dim(null);
      window.vmTooltip.hide();
    });
  }

  function openAssetModal(row, ctx) {
    const overlay = ensureAssetModal();
    const body = overlay.querySelector("#assetModalBody");
    window._assetModalContext = { row, ctx };

    const crit = criticalityMeta(row.criticality);
    const emptyRisk = ctx.totalActive === 0;
    const riskCls = emptyRisk ? "assets-risk-pill--none" : riskPillClass(ctx.maxSev);
    const riskText = riskLabel(ctx.maxSev, emptyRisk);

    const sum = ctx.counts.critical + ctx.counts.high + ctx.counts.medium + ctx.counts.low + ctx.counts.info;
    const barParts = [
      { k: "critical", c: ctx.counts.critical, col: "#f07178" },
      { k: "high", c: ctx.counts.high, col: "#ffab70" },
      { k: "medium", c: ctx.counts.medium, col: "#e7c66f" },
      { k: "low", c: ctx.counts.low, col: "#7fd99a" },
      { k: "info", c: ctx.counts.info, col: "#7eb8ff" },
    ];

    let barHtml = `<div class="asset-modal__bar-wrap">
      <div id="assetSevBar" class="asset-modal__bar-flex">`;
    if (sum === 0) {
      barHtml += `<div class="asset-modal__bar-empty">Нет активных находок для распределения</div>`;
    } else {
      barParts.forEach((p) => {
        if (!p.c) return;
        const w = (p.c / sum) * 100;
        barHtml += `<div class="asset-bar-seg" data-sev="${escapeHtml(p.k)}" data-val="${p.c}" data-total="${sum}" style="width:${w.toFixed(
          2
        )}%;background:${p.col};"></div>`;
      });
    }
    barHtml += `</div></div>`;

    const portsHtml = ctx.ports.length
      ? ctx.ports
          .slice(0, 48)
          .map((p) => `<span class="asset-modal__port">${escapeHtml(p)}</span>`)
          .join("")
      : `<span style="color:rgba(180,195,210,.65);font-size:.85rem;">${escapeHtml(RU.modal.none)}</span>`;

    const findingsSorted = (ctx.related || []).slice().sort((a, b) => {
      const ca = toNum(a.cvss_score ?? a.cvssbase ?? a.cvss_base, 0);
      const cb = toNum(b.cvss_score ?? b.cvssbase ?? b.cvss_base, 0);
      return cb - ca;
    });
    const findingsHtml = renderFindingCardsForModal(row, findingsSorted);

    if (body) {
      body.innerHTML = `
        <div class="asset-modal__hero">
          <div>
            <h2 class="asset-modal__name">${escapeHtml(row.name)}</h2>
            <div class="asset-modal__ip">${escapeHtml(row.ip || RU.modal.none)} · ${escapeHtml(
              row.type || "тип не указан"
            )}</div>
            <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
              <span class="assets-risk-pill ${riskCls}">${escapeHtml(riskText)}</span>
              <span class="assets-risk-pill ${crit.cls}">Учёт: ${escapeHtml(crit.label)}</span>
            </div>
          </div>
          <div class="asset-modal__score">
            <div class="asset-modal__score-val">${emptyRisk ? "—" : escapeHtml(toNum(ctx.maxCvss, 0).toFixed(1))}</div>
            <div class="asset-modal__score-label">${escapeHtml(RU.modal.maxCvss)}</div>
          </div>
        </div>

        <div class="asset-modal__grid">
          <div class="asset-modal__stat">
            <div class="asset-modal__stat-label">${escapeHtml(RU.modal.open)}</div>
            <div class="asset-modal__stat-value">${ctx.openCount}</div>
          </div>
          <div class="asset-modal__stat">
            <div class="asset-modal__stat-label">${escapeHtml(RU.modal.total)}</div>
            <div class="asset-modal__stat-value">${ctx.total}</div>
          </div>
          <div class="asset-modal__stat">
            <div class="asset-modal__stat-label">${escapeHtml(RU.modal.lastSeen)}</div>
            <div class="asset-modal__stat-value" style="font-size:.95rem;font-weight:700;">${escapeHtml(
              ctx.lastDetected || RU.modal.none
            )}</div>
          </div>
        </div>

        <div class="asset-modal__section-title">${escapeHtml(RU.modal.severity)}</div>
        ${barHtml}

        <div class="asset-modal__section-title">${escapeHtml(RU.modal.ports)}</div>
        <p style="margin:0 0 8px;font-size:12px;color:rgba(160,180,200,.7);">${escapeHtml(RU.modal.portsHint)}</p>
        <div class="asset-modal__ports">${portsHtml}</div>

        <div class="asset-modal__section-title">${escapeHtml(RU.modal.findingsList)}</div>
        <div class="findings-list asset-modal__findings">${findingsHtml}</div>
      `;
    }

    window.vmTooltip?.ensure();
    setTimeout(() => wireAssetSeverityBar(ctx), 0);

    lockBodyScroll(true);
    overlay.style.display = "flex";
  }

  // ===== sorting (таблица) =====
  function sortIndicator(sortState, key) {
    const idx = sortState.findIndex((s) => s.key === key);
    if (idx === -1) return { text: "", off: true };
    const s = sortState[idx];
    return { text: s.dir === "asc" ? "↑" : "↓", off: false };
  }

  function compareValues(a, b, key) {
    if (key === "ip") {
      const na = ipToNum(a.ip);
      const nb = ipToNum(b.ip);
      if (na !== null && nb !== null) return na - nb;
      return a.ip.localeCompare(b.ip);
    }
    if (key === "risk") return (a._riskRank || 0) - (b._riskRank || 0);
    if (key === "findings") return (a._open || 0) - (b._open || 0);
    const va = safeStr(a[key]).trim();
    const vb = safeStr(b[key]).trim();
    return va.localeCompare(vb, "ru", { sensitivity: "base" });
  }

  function applySort(items, sortState) {
    if (!sortState.length) return items;
    const arr = items.slice();
    arr.sort((a, b) => {
      for (const s of sortState) {
        const c = compareValues(a, b, s.key);
        if (c !== 0) return s.dir === "asc" ? c : -c;
      }
      return 0;
    });
    return arr;
  }

  function toggleSort(state, key, multi) {
    const curIdx = state.sort.findIndex((s) => s.key === key);
    if (!multi) {
      if (curIdx === -1) state.sort = [{ key, dir: "asc" }];
      else state.sort = [{ key, dir: state.sort[curIdx].dir === "asc" ? "desc" : "asc" }];
      return;
    }
    if (curIdx === -1) state.sort = state.sort.concat([{ key, dir: "asc" }]);
    else {
      const nextDir = state.sort[curIdx].dir === "asc" ? "desc" : "asc";
      state.sort = state.sort.map((s, i) => (i === curIdx ? { key, dir: nextDir } : s));
    }
  }

  window.pages.assets = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">${RU.title}</div>
          <div class="card assets-layout findings-layout" style="margin-top:20px;">
            <div class="card-body" id="assetsContainer">Загрузка…</div>
          </div>
        </div>
      `;
    },

    async init() {
      const data = await ensureData();
      const rawAssets =
        typeof dataLoader.getAssets === "function" ? dataLoader.getAssets() : data.assets || [];
      const allFindings = Array.isArray(data.findings) ? data.findings : [];

      const el = document.getElementById("assetsContainer");
      if (!el) return;

      const rows = (rawAssets || []).map(normalizeRow);
      if (!rows.length) {
        el.innerHTML = `<div class="vm-placeholder"><p class="vm-placeholder__lead">Нет активов в датасете</p></div>`;
        return;
      }

      const rankMap = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      const enriched = rows.map((row) => {
        const ctx = computeContext(row, allFindings);
        const emptyRisk = ctx.totalActive === 0;
        const rk = emptyRisk ? 0 : rankMap[ctx.maxSev] || 0;
        return {
          ...row,
          _ctx: ctx,
          _riskRank: rk,
          _open: ctx.openCount,
          _portsPreview: ctx.ports.slice(0, 3).join(", ") + (ctx.ports.length > 3 ? "…" : ""),
        };
      });

      window._assetsById = new Map(enriched.map((r) => [String(r.id), r]));

      const types = uniq(enriched.map((a) => a.type)).sort((x, y) => x.localeCompare(y, "ru"));
      const zones = uniq(enriched.map((a) => a.zone)).sort((x, y) => x.localeCompare(y, "ru"));
      const teams = uniq(enriched.map((a) => a.team)).sort((x, y) => x.localeCompare(y, "ru"));

      const state = {
        filters: { name: "", ip: "", type: "", zone: "", team: "" },
        sort: [{ key: "risk", dir: "desc" }],
        quick: "",
      };

      el.innerHTML = `
        <div class="assets-page">
          <div class="assets-toolbar">
            <div class="assets-toolbar__title">Поиск</div>
            <input type="search" class="assets-toolbar__search" id="assetsQuickSearch" placeholder="${escapeHtml(
              RU.search
            )}" autocomplete="off" />
          </div>
          <div class="assets-main">
            <div class="assets-table-wrap" id="assetsTableWrap">
              <table class="assets-table">
                <thead>
                  <tr>
                    <th><div class="th-sort" data-sort="name"><span>${RU.cols.name}</span><span class="sort-ind off" data-ind="name"></span></div></th>
                    <th><div class="th-sort" data-sort="ip"><span>${RU.cols.ip}</span><span class="sort-ind off" data-ind="ip"></span></div></th>
                    <th><div class="th-sort" data-sort="risk"><span>${RU.cols.risk}</span><span class="sort-ind off" data-ind="risk"></span></div></th>
                    <th><div class="th-sort" data-sort="findings"><span>${RU.cols.findings}</span><span class="sort-ind off" data-ind="findings"></span></div></th>
                    <th>${RU.cols.ports}</th>
                    <th><div class="th-sort" data-sort="type"><span>${RU.cols.type}</span><span class="sort-ind off" data-ind="type"></span></div></th>
                    <th><div class="th-sort" data-sort="zone"><span>${RU.cols.zone}</span><span class="sort-ind off" data-ind="zone"></span></div></th>
                    <th><div class="th-sort" data-sort="team"><span>${RU.cols.team}</span><span class="sort-ind off" data-ind="team"></span></div></th>
                  </tr>
                  <tr class="filters">
                    <th><input class="assets-filter" data-filter="name" placeholder="Фильтр" autocomplete="off" /></th>
                    <th><input class="assets-filter" data-filter="ip" placeholder="Фильтр" autocomplete="off" /></th>
                    <th></th>
                    <th></th>
                    <th></th>
                    <th><select class="assets-filter" data-filter="type"><option value="">Все</option>${types
                      .map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`)
                      .join("")}</select></th>
                    <th><select class="assets-filter" data-filter="zone"><option value="">Все</option>${zones
                      .map((z) => `<option value="${escapeHtml(z)}">${escapeHtml(z)}</option>`)
                      .join("")}</select></th>
                    <th><select class="assets-filter" data-filter="team"><option value="">Все</option>${teams
                      .map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`)
                      .join("")}</select></th>
                  </tr>
                </thead>
                <tbody id="assetsTbody"></tbody>
              </table>
            </div>
          </div>
        </div>`;

      const elWrap = document.getElementById("assetsTableWrap");
      const elTbody = document.getElementById("assetsTbody");
      const elQuick = document.getElementById("assetsQuickSearch");
      const indEls = {
        name: el.querySelector('[data-ind="name"]'),
        ip: el.querySelector('[data-ind="ip"]'),
        risk: el.querySelector('[data-ind="risk"]'),
        findings: el.querySelector('[data-ind="findings"]'),
        type: el.querySelector('[data-ind="type"]'),
        zone: el.querySelector('[data-ind="zone"]'),
        team: el.querySelector('[data-ind="team"]'),
      };

      function updateSortIndicators() {
        for (const k of Object.keys(indEls)) {
          const ind = sortIndicator(state.sort, k);
          const elInd = indEls[k];
          if (!elInd) continue;
          elInd.textContent = ind.text;
          elInd.classList.toggle("off", !!ind.off);
        }
      }

      function renderRows(items) {
        if (!elTbody) return;
        elTbody.innerHTML = items
          .map((a) => {
            const ctx = a._ctx;
            const emptyRisk = ctx.totalActive === 0;
            const cls = emptyRisk ? "assets-risk-pill--none" : riskPillClass(ctx.maxSev);
            const lab = riskLabel(ctx.maxSev, emptyRisk);
            const findStr = `${a._open} / ${ctx.total}`;
            return `
              <tr data-asset-id="${escapeHtml(String(a.id))}">
                <td class="truncate" title="${escapeHtml(a.name)}">${escapeHtml(a.name)}</td>
                <td>${escapeHtml(a.ip)}</td>
                <td><span class="assets-risk-pill ${cls}">${escapeHtml(lab)}</span></td>
                <td>${escapeHtml(findStr)}</td>
                <td class="truncate" title="${escapeHtml(a._portsPreview || "")}">${escapeHtml(
                  a._portsPreview || RU.modal.none
                )}</td>
                <td>${escapeHtml(a.type)}</td>
                <td>${escapeHtml(a.zone)}</td>
                <td>${escapeHtml(a.team)}</td>
              </tr>`;
          })
          .join("");
      }

      function applyFiltersAndRender() {
        const f = state.filters;
        const q = lower(state.quick);
        let out = enriched;

        if (f.name) out = out.filter((a) => lower(a.name).includes(lower(f.name)));
        if (f.ip) out = out.filter((a) => lower(a.ip).includes(lower(f.ip)));
        if (f.type) out = out.filter((a) => a.type === f.type);
        if (f.zone) out = out.filter((a) => a.zone === f.zone);
        if (f.team) out = out.filter((a) => a.team === f.team);

        if (q) {
          out = out.filter(
            (a) => lower(a.name).includes(q) || lower(a.ip).includes(q) || lower(a.type).includes(q)
          );
        }

        out = applySort(out, state.sort);
        updateSortIndicators();
        renderRows(out);
      }

      elWrap?.addEventListener("click", (e) => {
        const th = e.target?.closest?.(".th-sort");
        if (th) {
          const key = th.getAttribute("data-sort");
          if (!key) return;
          toggleSort(state, key, !!e.shiftKey);
          applyFiltersAndRender();
          return;
        }
        const tr = e.target?.closest?.("tr[data-asset-id]");
        if (!tr) return;
        const id = tr.getAttribute("data-asset-id");
        const row = window._assetsById?.get(String(id));
        if (!row) return;
        const ctx = computeContext(row, allFindings);
        openAssetModal(row, ctx);
      });

      elWrap?.addEventListener("input", (e) => {
        const inp = e.target?.closest?.("input[data-filter]");
        if (!inp) return;
        const key = inp.getAttribute("data-filter");
        if (!key) return;
        state.filters[key] = safeStr(inp.value);
        applyFiltersAndRender();
      });

      elWrap?.addEventListener("change", (e) => {
        const sel = e.target?.closest?.("select[data-filter]");
        if (!sel) return;
        const key = sel.getAttribute("data-filter");
        if (!key) return;
        state.filters[key] = safeStr(sel.value);
        applyFiltersAndRender();
      });

      elQuick?.addEventListener("input", () => {
        state.quick = safeStr(elQuick.value);
        applyFiltersAndRender();
      });

      if (!window._assetModalEsc) {
        window._assetModalEsc = true;
        document.addEventListener("keydown", (e) => {
          if (e.key === "Escape") closeAssetModal();
        });
      }

      applyFiltersAndRender();
    },
  };
})();
