// js/pages/scans.js
(() => {
  "use strict";
  window.pages = window.pages || {};

  window.pages.scans = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">Сканы</div>
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
    async init() {},
  };
})();
