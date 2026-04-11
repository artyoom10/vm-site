// js/pages/dashboard.js
(() => {
  "use strict";
  window.pages = window.pages || {};

  const RU = {
    pageTitle: "Дашборд",
    kpiAssets: "Активы",
    kpiFindings: "Уязвимости",
    kpiCritical: "Критические",
    kpiResolved: "Устранено",
    kpiOpen: "Открыто",
    intro:
      "Сводка по датасету сканирования: распределение серьёзности и топ хостов по количеству находок.",

    chartTitle: "Критичность уязвимостей",
    chartHostsTitle: "Уязвимости по хостам",

    findings: "Уязвимости",
    findingsCount: "уязвимостей",
    loading: "Загрузка…",
    noData: "Нет данных",

    tableHost: "Хост",
    tableTotal: "Всего",
    distribution: "Распределение",
    sev: {
      critical: "Критический",
      high: "Высокий",
      medium: "Средний",
      low: "Низкий",
      info: "Инфо",
    },
  };

  const COLORS = {
    critical: "#F44336",
    high: "#FF9800",
    medium: "#FFC107",
    low: "#4CAF50",
    info: "#2196F3",
  };

  // слева направо: инфо, низкий, средний, высокий, критический
  const SEV_ORDER = ["info", "low", "medium", "high", "critical"];

  let dashboardGlobalHooksBound = false;

  function safeStr(v) {
    return v === null || v === undefined ? "" : String(v);
  }
  function lower(v) {
    return safeStr(v).trim().toLowerCase();
  }
  function pct(val, total) {
    if (!total) return 0;
    return Math.round((Number(val || 0) / total) * 100);
  }
  function sevLabel(key) {
    const k = lower(key);
    return RU.sev[k] || key;
  }
  function hostLabel(f) {
    // поля нормализации findings [file:284]
    return (
      safeStr(
        f.affected_asset ||
          f.hostname ||
          f.ip ||
          f.assetname ||
          f.asset_id ||
          "-"
      ).trim() || "-"
    );
  }

  function showTooltipAt(opts) {
    const vt = window.vmTooltip;
    if (!vt) return;
    vt.showAt({ ...opts, subtitle: RU.findingsCount });
  }

  function hideTooltip() {
    window.vmTooltip?.hide();
  }

  function countBySeverity(findings) {
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings || []) {
      const sev = lower(f.severity) || "info"; // [file:284]
      if (sev === "critical") out.critical++;
      else if (sev === "high") out.high++;
      else if (sev === "medium") out.medium++;
      else if (sev === "low") out.low++;
      else out.info++;
    }
    return out;
  }

  // ===== DONUT (без gap, как раньше) =====
  function donutHtml({ counts, total }) {
    const order = ["critical", "high", "medium", "low", "info"];

    const size = 420;
    const cx = size / 2;
    const cy = size / 2;

    const r = 145;
    const stroke = 24;
    const c = 2 * Math.PI * r;

    // старт с 12 часов
    let offset = c * 0.25;

    const ringBg = `
      <circle cx="${cx}" cy="${cy}" r="${r}"
        fill="none"
        stroke="rgba(255,255,255,.08)"
        stroke-width="${stroke}"
      />
    `;

    let segs = "";
    for (const key of order) {
      const val = Number(counts[key] || 0);
      if (!val || total <= 0) continue;

      const len = (val / total) * c;

      segs += `
        <circle
          class="donut-seg"
          data-key="${key}"
          data-value="${val}"
          cx="${cx}" cy="${cy}" r="${r}"
          fill="none"
          stroke="${COLORS[key]}"
          stroke-width="${stroke}"
          stroke-linecap="round"
          stroke-dasharray="${len} ${c - len}"
          stroke-dashoffset="${offset}"
          style="cursor:pointer; transition: opacity .12s ease, filter .12s ease;"
        />
      `;

      offset -= len;
    }

    const centerText = `
      <text x="${cx}" y="${cy - 8}" text-anchor="middle"
        font-size="54" font-weight="900"
        fill="var(--color-text)"
        id="donutCenterValue"
      >${total}</text>

      <text x="${cx}" y="${cy + 28}" text-anchor="middle"
        font-size="13" font-weight="800"
        fill="var(--color-text-secondary)"
        id="donutCenterLabel"
      >${RU.findings}</text>
    `;

    return `
      <div style="display:flex; justify-content:center; padding: 12px 6px 6px;">
        <div id="donutBox" style="position:relative; width:${size}px; height:${size}px;">
          <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
            ${ringBg}
            ${segs}
            ${centerText}
          </svg>
        </div>
      </div>
    `;
  }

  function wireDonutInteractions({ total }) {
    const box = document.getElementById("donutBox");
    const centerValue = document.getElementById("donutCenterValue");
    const centerLabel = document.getElementById("donutCenterLabel");
    if (!box || !centerValue || !centerLabel) return;

    const segs = box.querySelectorAll(".donut-seg");

    function setCenter(label, value) {
      centerValue.textContent = String(value);
      centerLabel.textContent = label;
    }

    function dimOthers(activeEl) {
      segs.forEach((x) => {
        if (!activeEl) {
          x.style.opacity = "1";
          x.style.filter = "none";
        } else if (x === activeEl) {
          x.style.opacity = "1";
          x.style.filter = "drop-shadow(0 0 10px rgba(255,255,255,.12))";
        } else {
          x.style.opacity = "0.28";
          x.style.filter = "none";
        }
      });
    }

    segs.forEach((el) => {
      el.addEventListener("mouseenter", () => {
        const key = safeStr(el.getAttribute("data-key"));
        const val = Number(el.getAttribute("data-value") || 0);
        const label = sevLabel(key);

        dimOthers(el);
        setCenter(label, val);
      });

      el.addEventListener("mouseleave", () => {
        dimOthers(null);
        setCenter(RU.findings, total);
        hideTooltip();
      });

      el.addEventListener("mousemove", (ev) => {
        // tooltip всегда СНАРУЖИ диаграммы: справа от контейнера (или слева, если нет места)
        const boxRect = box.getBoundingClientRect();

        const key = safeStr(el.getAttribute("data-key"));
        const val = Number(el.getAttribute("data-value") || 0);

        window.vmTooltip?.ensure();
        const tooltip = document.getElementById("vmGlobalTooltip");
        if (tooltip) tooltip.style.display = "block";
        const tw = tooltip?.getBoundingClientRect().width || 260;

        const rightX = boxRect.right + 16;
        const leftX = boxRect.left - tw - 16;

        const x = rightX + tw < window.innerWidth ? rightX : Math.max(12, leftX);
        const y = ev.clientY;

        showTooltipAt({
          x,
          y,
          title: sevLabel(key),
          value: val,
          percent: window.vmTooltip ? window.vmTooltip.pct(val, total) : pct(val, total),
          color: COLORS[lower(key)] || "#999",
        });
      });
    });

    box.addEventListener("mouseleave", () => {
      dimOthers(null);
      setCenter(RU.findings, total);
      hideTooltip();
    });
  }

  // ===== HOSTS LIST (как у тебя уже хорошо) =====
  function hostsStackedBarsHtml({ findings }) {
    const map = new Map();

    for (const f of findings || []) {
      const h = hostLabel(f);
      if (!h || h === "-") continue;

      const sev = lower(f.severity) || "info";
      const bucket =
        sev === "critical" || sev === "high" || sev === "medium" || sev === "low" || sev === "info"
          ? sev
          : "info";

      if (!map.has(h)) {
        map.set(h, { host: h, total: 0, info: 0, low: 0, medium: 0, high: 0, critical: 0 });
      }
      const row = map.get(h);
      row.total++;
      row[bucket]++;
    }

    const rows = Array.from(map.values()).sort((a, b) => b.total - a.total);
    if (!rows.length) {
      return `<div style="color: var(--color-text-secondary); padding: 6px 0;">${RU.noData}</div>`;
    }

    const list = rows
      .map((r) => {
        const segs = SEV_ORDER.map((k) => {
          const v = Number(r[k] || 0);
          const w = r.total ? (v / r.total) * 100 : 0;

          return `
            <div
              class="host-seg"
              data-sev="${k}"
              data-count="${v}"
              data-total="${r.total}"
              style="
                width:${w}%;
                height:100%;
                background:${COLORS[k]};
                cursor:pointer;
              "
            ></div>
          `;
        }).join("");

        return `
          <div style="
            display:grid;
            grid-template-columns: minmax(180px, 340px) 1fr 74px;
            gap: 12px;
            align-items:center;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,.06);
          ">
            <div title="${safeStr(r.host)}" style="
              overflow:hidden;
              text-overflow:ellipsis;
              white-space:nowrap;
              font-weight:900;
              color: var(--color-text);
            ">${safeStr(r.host)}</div>

            <div style="
              height: 16px;
              border-radius: 999px;
              background: rgba(255,255,255,.06);
              border: 1px solid rgba(255,255,255,.10);
              overflow:hidden;
              display:flex;
            ">
              ${segs}
            </div>

            <div style="text-align:right; font-weight:900; color: var(--color-text);">
              ${r.total}
            </div>
          </div>
        `;
      })
      .join("");

    return `
      <div id="hostsBox" style="position:relative;">
        <div style="
          display:grid;
          grid-template-columns: minmax(180px, 340px) 1fr 74px;
          gap: 12px;
          align-items:center;
          padding: 0 0 10px;
          color: var(--color-text-secondary);
          font-size: 12px;
          font-weight: 900;
        ">
          <div>${RU.tableHost}</div>
          <div>${RU.distribution}</div>
          <div style="text-align:right;">${RU.tableTotal}</div>
        </div>

        ${list}
      </div>
    `;
  }

  function wireHostsTooltip() {
    const box = document.getElementById("hostsBox");
    if (!box) return;

    const segs = box.querySelectorAll(".host-seg");

    function dimRow(activeEl) {
      const bar = activeEl?.parentElement;
      if (!bar) return;
      bar.querySelectorAll(".host-seg").forEach((x) => {
        if (x === activeEl) {
          x.style.opacity = "1";
          x.style.filter = "drop-shadow(0 0 8px rgba(255,255,255,.10))";
        } else {
          x.style.opacity = "0.30";
          x.style.filter = "none";
        }
      });
    }
    function clearDim(activeEl) {
      const bar = activeEl?.parentElement;
      if (!bar) return;
      bar.querySelectorAll(".host-seg").forEach((x) => {
        x.style.opacity = "1";
        x.style.filter = "none";
      });
    }

    segs.forEach((el) => {
      el.addEventListener("mouseenter", () => {
        dimRow(el);
      });

      el.addEventListener("mouseleave", () => {
        clearDim(el);
        hideTooltip();
      });

      el.addEventListener("mousemove", (ev) => {
        const sev = lower(el.getAttribute("data-sev"));
        const count = Number(el.getAttribute("data-count") || 0);
        const total = Number(el.getAttribute("data-total") || 0);

        showTooltipAt({
          x: ev.clientX,
          y: ev.clientY,
          title: sevLabel(sev),
          value: count,
          percent: window.vmTooltip ? window.vmTooltip.pct(count, total) : pct(count, total),
          color: COLORS[sev] || "#999",
        });
      });
    });

    box.addEventListener("mouseleave", () => {
      box.querySelectorAll(".host-seg").forEach((x) => {
        x.style.opacity = "1";
        x.style.filter = "none";
      });
      hideTooltip();
    });
  }

  // ===== PAGE =====
  window.pages.dashboard = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">${RU.pageTitle}</div>
          <p class="dashboard-intro">${RU.intro}</p>
          <p class="dashboard-meta" id="dashboardMeta"></p>

          <div class="kpi-grid dashboard-kpi">
            <div class="kpi-card">
              <div class="kpi-label">${RU.kpiAssets}</div>
              <div class="kpi-value success" id="kpiAssets">0</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">${RU.kpiFindings}</div>
              <div class="kpi-value critical" id="kpiFindings">0</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">${RU.kpiOpen}</div>
              <div class="kpi-value critical" id="kpiOpen">0</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">${RU.kpiCritical}</div>
              <div class="kpi-value critical" id="kpiCritical">0</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">${RU.kpiResolved}</div>
              <div class="kpi-value success" id="kpiResolved">0</div>
            </div>
          </div>

          <div class="card dashboard-chart-card" style="margin-top: 20px;">
            <div class="card-body" style="padding: 18px 18px 12px;">
              <div class="dashboard-chart-head">
                <span class="dashboard-chart-head__title">${RU.chartTitle}</span>
              </div>
              <div id="dashboardDonut" style="margin-top: 8px;">${RU.loading}</div>
            </div>
          </div>

          <div class="card dashboard-chart-card" style="margin-top: 20px;">
            <div class="card-body" style="padding: 18px;">
              <div class="dashboard-chart-head">
                <span class="dashboard-chart-head__title">${RU.chartHostsTitle}</span>
              </div>
              <div id="dashboardHostsBars">${RU.loading}</div>
            </div>
          </div>
        </div>
      `;
    },

    async init() {
      if (!dataLoader.data && typeof dataLoader.loadDataset === "function") {
        await dataLoader.loadDataset();
      } else if (!dataLoader.data && typeof dataLoader.loadApplicationData === "function") {
        dataLoader.data = await dataLoader.loadApplicationData();
      }

      const data = dataLoader.data || {};
      const findings = Array.isArray(data.findings) ? data.findings : [];
      const assets = Array.isArray(data.assets) ? data.assets : [];

      const stats = typeof dataLoader.getStats === "function" ? dataLoader.getStats() : null;

      document.getElementById("kpiAssets").textContent = String(stats?.totalAssets ?? assets.length);
      document.getElementById("kpiFindings").textContent = String(stats?.totalFindings ?? findings.length);
      const openEl = document.getElementById("kpiOpen");
      if (openEl) {
        openEl.textContent = String(
          stats?.openCount ?? findings.filter((f) => (f.status_key || lower(f.status)) === "open").length
        );
      }
      document.getElementById("kpiCritical").textContent = String(
        stats?.criticalCount ?? findings.filter((f) => lower(f.severity) === "critical").length
      );
      document.getElementById("kpiResolved").textContent = String(
        stats?.resolvedCount ??
          findings.filter((f) => (f.status_key || lower(f.status)) === "resolved").length
      );

      const metaEl = document.getElementById("dashboardMeta");
      const genAt = data.metadata?.generated_at || data.metadata?.generatedAt;
      if (metaEl) {
        metaEl.textContent = genAt
          ? `Снимок данных: ${safeStr(genAt)}`
          : "Используйте разделы «Уязвимости» и «Отчёты» для детализации по отделам.";
      }

      window.vmTooltip?.ensure();

      // Donut
      const total = findings.length;
      const counts = countBySeverity(findings);
      const donutWrap = document.getElementById("dashboardDonut");
      if (donutWrap) {
        donutWrap.innerHTML = donutHtml({ counts, total });
        wireDonutInteractions({ total });
      }

      // Hosts list
      const barsWrap = document.getElementById("dashboardHostsBars");
      if (barsWrap) {
        barsWrap.innerHTML = hostsStackedBarsHtml({ findings });
        wireHostsTooltip();
      }

      if (!dashboardGlobalHooksBound) {
        dashboardGlobalHooksBound = true;
        window.addEventListener("scroll", hideTooltip, { passive: true });
        window.addEventListener("resize", hideTooltip, { passive: true });
      }
    },
  };
})();
