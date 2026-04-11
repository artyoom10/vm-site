// js/pages/settings.js
(() => {
  "use strict";
  window.pages = window.pages || {};

  window.pages.settings = {
    render() {
      return `
        <div class="page-wrapper">
          <div class="page-title">Настройки</div>
          <div class="card" style="margin-top:20px;">
            <div class="card-body vm-placeholder">
              <p class="vm-placeholder__lead">Параметры учётной записи</p>
              <p class="vm-placeholder__text">
                Здесь можно будет задать уведомления, тайм-зону и параметры интеграций. Аутентификация
                выполняется через Supabase; сессия обновляется автоматически.
              </p>
              <div class="vm-placeholder__hint">
                Общий визуальный стиль совпадает с разделами «Уязвимости», «Активы» и «Отчёты».
              </div>
            </div>
          </div>
        </div>
      `;
    },
    async init() {},
  };
})();
