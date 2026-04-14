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
    if (state.mode === "xml") return `Источник: XML (${esc(state.label || "report.xml")})`;
    return "Источник: dataset.json";
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
                Выберите, откуда брать данные для вкладок «Дашборд», «Активы», «Уязвимости».
                Загруженный XML хранится только в памяти текущей сессии браузера.
              </p>
              <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:10px;">
                <label style="display:inline-flex;gap:8px;align-items:center;">
                  <input type="radio" name="scanDataSource" value="json" />
                  <span>JSON датасет</span>
                </label>
                <label style="display:inline-flex;gap:8px;align-items:center;">
                  <input type="radio" name="scanDataSource" value="xml" />
                  <span>Загруженный XML</span>
                </label>
                <button type="button" class="btn btn--secondary" id="scanUploadXmlBtn">+ Загрузить отчёт XML</button>
                <input type="file" id="scanUploadXmlInput" accept=".xml,text/xml,application/xml" style="display:none;" />
              </div>
              <div class="vm-placeholder__hint" id="scanSourceMeta" style="margin-top:10px;">
                ${renderSourceMeta()}
              </div>
              <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;">
                <button class="btn btn--secondary" type="button" id="goDashboardBtn">Открыть Дашборд</button>
                <button class="btn btn--secondary" type="button" id="goAssetsBtn">Открыть Активы</button>
                <button class="btn btn--secondary" type="button" id="goFindingsBtn">Открыть Уязвимости</button>
              </div>
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
      const sourceInputs = Array.from(document.querySelectorAll('input[name="scanDataSource"]'));
      const uploadBtn = document.getElementById("scanUploadXmlBtn");
      const uploadInput = document.getElementById("scanUploadXmlInput");
      const sourceMeta = document.getElementById("scanSourceMeta");

      function refreshSourceUi() {
        const state = dataLoader.getSourceState ? dataLoader.getSourceState() : { mode: "json", hasXml: false };
        sourceInputs.forEach((el) => {
          el.checked = el.value === state.mode;
          if (el.value === "xml") el.disabled = !state.hasXml;
        });
        if (sourceMeta) {
          sourceMeta.textContent =
            state.mode === "xml"
              ? `Источник: XML (${state.label || "report.xml"})`
              : "Источник: dataset.json";
        }
      }

      sourceInputs.forEach((el) => {
        el.addEventListener("change", () => {
          if (!el.checked) return;
          try {
            dataLoader.setSourceMode(el.value);
            refreshSourceUi();
            window.utils?.showNotification?.("Источник данных переключён", "success");
          } catch (e) {
            window.utils?.showNotification?.(String(e.message || e), "error");
            refreshSourceUi();
          }
        });
      });

      if (uploadBtn && uploadInput) {
        uploadBtn.addEventListener("click", () => uploadInput.click());
        uploadInput.addEventListener("change", async () => {
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
      }

      document.getElementById("goDashboardBtn")?.addEventListener("click", () => window.router?.navigate("dashboard"));
      document.getElementById("goAssetsBtn")?.addEventListener("click", () => window.router?.navigate("assets"));
      document.getElementById("goFindingsBtn")?.addEventListener("click", () => window.router?.navigate("findings"));

      refreshSourceUi();
    },
  };
})();
