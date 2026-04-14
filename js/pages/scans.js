// js/pages/scans.js
(() => {
  "use strict";
  window.pages = window.pages || {};

  function esc(s) {
    const v = s == null ? "" : String(s);
    return v
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function renderSourceMeta() {
    const state = window.dataLoader?.getSourceState ? dataLoader.getSourceState() : null;
    if (!state) return "Источник: dataset.json";
    if (state.mode === "mixed") return `Источник: JSON + XML (${esc(state.label || "report.xml")})`;
    if (state.mode === "xml") return `Источник: XML (${esc(state.label || "report.xml")})`;
    return "Источник: dataset.json";
  }

  function onOff(v) {
    return v ? "checked" : "";
  }

  function renderSwitch(id, checked, disabled = false) {
    return `
      <label style="display:inline-flex;align-items:center;gap:8px;cursor:${disabled ? "not-allowed" : "pointer"};">
        <span style="font-size:12px;color:var(--color-text-secondary);">Использовать</span>
        <span style="position:relative;display:inline-block;width:44px;height:24px;">
          <input type="checkbox" id="${id}" ${onOff(checked)} ${disabled ? "disabled" : ""} style="opacity:0;width:0;height:0;" />
          <span style="
            position:absolute;inset:0;border-radius:999px;
            background:${checked ? "rgba(45,212,191,.45)" : "rgba(255,255,255,.18)"};
            border:1px solid ${checked ? "rgba(45,212,191,.75)" : "rgba(255,255,255,.2)"};
            transition:all .18s ease;
          "></span>
          <span style="
            position:absolute;top:2px;left:${checked ? "22px" : "2px"};width:18px;height:18px;border-radius:50%;
            background:${checked ? "#2dd4bf" : "#c8d0dd"};box-shadow:0 1px 8px rgba(0,0,0,.35);transition:all .18s ease;
          "></span>
        </span>
      </label>
    `;
  }

  function renderJsonCard(state) {
    const m = state?.jsonMeta || {};
    return `
      <div class="card" style="margin-top:14px;">
        <div class="card-body vm-placeholder" style="padding:16px;">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;">
            <p class="vm-placeholder__lead" style="margin:0;">JSON датасет</p>
            ${renderSwitch("scanSourceJsonToggle", state?.enabled?.json !== false, false)}
          </div>
          <div class="vm-placeholder__hint" style="margin-top:8px;">Источник: <code>/api/dataset.php</code></div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-top:10px;">
            <div class="asset-modal__stat"><div class="asset-modal__stat-label">Активы</div><div class="asset-modal__stat-value">${Number(m.assets || 0)}</div></div>
            <div class="asset-modal__stat"><div class="asset-modal__stat-label">Уязвимости</div><div class="asset-modal__stat-value">${Number(m.findings || 0)}</div></div>
            <div class="asset-modal__stat"><div class="asset-modal__stat-label">Записи сканов</div><div class="asset-modal__stat-value">${Number(m.scans || 0)}</div></div>
          </div>
          <div class="vm-placeholder__hint" style="margin-top:8px;">Снимок: ${esc(m.generatedAt || "—")}</div>
        </div>
      </div>
    `;
  }

  function renderXmlCard(state) {
    const hasXml = Boolean(state?.hasXml);
    const m = state?.xmlMeta || {};
    return `
      <div class="card" style="margin-top:14px;">
        <div class="card-body vm-placeholder" style="padding:16px;">
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;">
            <p class="vm-placeholder__lead" style="margin:0;">XML отчёт</p>
            ${renderSwitch("scanSourceXmlToggle", state?.enabled?.xml, !hasXml)}
          </div>
          ${
            hasXml
              ? `
            <div class="vm-placeholder__hint" style="margin-top:8px;">Файл: ${esc(m.fileName || "report.xml")}</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-top:10px;">
              <div class="asset-modal__stat"><div class="asset-modal__stat-label">Сканер</div><div class="asset-modal__stat-value" style="font-size:.95rem;">${esc(m.scanner || "—")}</div></div>
              <div class="asset-modal__stat"><div class="asset-modal__stat-label">Формат</div><div class="asset-modal__stat-value" style="font-size:.95rem;">${esc(m.reportFormat || "XML")}</div></div>
              <div class="asset-modal__stat"><div class="asset-modal__stat-label">Статус</div><div class="asset-modal__stat-value">${esc(m.scanStatus || "—")}</div></div>
              <div class="asset-modal__stat"><div class="asset-modal__stat-label">Активы</div><div class="asset-modal__stat-value">${Number(m.assets || 0)}</div></div>
              <div class="asset-modal__stat"><div class="asset-modal__stat-label">Уязвимости</div><div class="asset-modal__stat-value">${Number(m.findings || 0)}</div></div>
              <div class="asset-modal__stat"><div class="asset-modal__stat-label">Загружен</div><div class="asset-modal__stat-value" style="font-size:.85rem;">${esc(
                m.loadedAt || "—"
              )}</div></div>
            </div>
            <div style="margin-top:10px;padding:10px 12px;border-radius:10px;background:rgba(45,212,191,.08);border:1px solid rgba(45,212,191,.25);">
              <div style="font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:rgba(180,195,210,.85);margin-bottom:4px;">Задача сканирования</div>
              <div style="font-size:1rem;font-weight:800;color:rgba(235,245,250,.95);margin-bottom:4px;">${esc(
                m.taskName || "—"
              )}</div>
              <div class="vm-placeholder__hint">Старт: ${esc(m.scanStart || "—")} · Снимок: ${esc(
                  m.generatedAt || "—"
                )}</div>
            </div>`
              : `<div class="vm-placeholder__hint" style="margin-top:8px;">XML ещё не загружен.</div>`
          }
        </div>
      </div>
    `;
  }

  window.pages.scans = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">Сканы</div>
          <div class="card" style="margin-top:20px;">
            <div class="card-body vm-placeholder">
              <p class="vm-placeholder__lead">Источник данных для аналитики</p>
              <p class="vm-placeholder__text">
                Выберите источники для вкладок «Дашборд», «Активы», «Уязвимости».
                Загруженный XML хранится только в памяти текущей сессии браузера.
              </p>
              <div style="margin-top:10px;">
                <button type="button" class="btn btn--secondary" id="scanUploadXmlBtn">+ Загрузить отчёт XML</button>
                <input type="file" id="scanUploadXmlInput" accept=".xml,text/xml,application/xml" style="display:none;" />
              </div>
              <div class="vm-placeholder__hint" id="scanSourceMeta" style="margin-top:10px;">
                ${renderSourceMeta()}
              </div>
              <div id="scanSourceCards"></div>
            </div>
          </div>
          <div class="card" style="margin-top:20px;">
            <div class="card-body vm-placeholder">
              <p class="vm-placeholder__lead">Задания сканирования</p>
              <p class="vm-placeholder__text">
                В этом разделе будет журнал запусков сканеров, расписание и статусы заданий — по аналогии с
                Nexpose, Qualys или OpenVAS/Greenbone. Сейчас данные берутся из снимка датасета; поле
                <code>scans</code> может быть пустым.
              </p>
              <div class="vm-placeholder__hint">
                План: фильтр по времени, привязка к активам, экспорт отчёта по скану.
              </div>
            </div>
          </div>
        </div>
      `;
    },
    async init() {
      const sourceMeta = document.getElementById("scanSourceMeta");
      const cardsWrap = document.getElementById("scanSourceCards");
      const uploadBtn = document.getElementById("scanUploadXmlBtn");
      const uploadInput = document.getElementById("scanUploadXmlInput");

      function refreshSourceUi() {
        const state = dataLoader.getSourceState
          ? dataLoader.getSourceState()
          : { mode: "json", enabled: { json: true, xml: false }, hasXml: false };
        if (sourceMeta) {
          sourceMeta.textContent =
            state.mode === "mixed"
              ? `Источник: JSON + XML (${state.label || "report.xml"})`
              : state.mode === "xml"
              ? `Источник: XML (${state.label || "report.xml"})`
              : "Источник: dataset.json";
        }
        if (cardsWrap) {
          cardsWrap.innerHTML = `${renderJsonCard(state)}${renderXmlCard(state)}`;
          wireCardEvents();
        }
      }

      function wireCardEvents() {
        const jsonToggle = document.getElementById("scanSourceJsonToggle");
        const xmlToggle = document.getElementById("scanSourceXmlToggle");

        jsonToggle?.addEventListener("change", () => {
          try {
            dataLoader.setSourceEnabled("json", Boolean(jsonToggle.checked));
            refreshSourceUi();
            window.utils?.showNotification?.("Источник данных обновлён", "success");
          } catch (e) {
            window.utils?.showNotification?.(String(e.message || e), "error");
            refreshSourceUi();
          }
        });

        xmlToggle?.addEventListener("change", () => {
          try {
            dataLoader.setSourceEnabled("xml", Boolean(xmlToggle.checked));
            refreshSourceUi();
            window.utils?.showNotification?.("Источник данных обновлён", "success");
          } catch (e) {
            window.utils?.showNotification?.(String(e.message || e), "error");
            refreshSourceUi();
          }
        });

      }

      uploadBtn?.addEventListener("click", () => uploadInput?.click());
      uploadInput?.addEventListener("change", async () => {
        const file = uploadInput.files && uploadInput.files[0];
        if (!file) return;
        try {
          const text = await file.text();
          const out = await dataLoader.loadXmlReportText(text, file.name);
          refreshSourceUi();
          window.utils?.showNotification?.(
            `XML загружен: активов ${out.meta.assets}, уязвимостей ${out.meta.findings}`,
            "success"
          );
        } catch (e) {
          window.utils?.showNotification?.(`Ошибка XML: ${String(e.message || e)}`, "error");
        } finally {
          uploadInput.value = "";
        }
      });

      await dataLoader.loadDataset();
      refreshSourceUi();
    },
  };
})();
