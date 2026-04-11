// js/router.js
(() => {
  "use strict";

  const DEFAULT_PAGE = "dashboard";

  function setActiveNav(page) {
    document.querySelectorAll(".navbar-item").forEach((btn) => {
      const p = btn.getAttribute("data-page");
      if (!p) return;
      btn.classList.toggle("active", p === page);
    });
  }

  function normalizePage(page) {
    const pages = window.pages || {};
    if (!page) return DEFAULT_PAGE;
    return pages[page] ? page : DEFAULT_PAGE;
  }

  function getPageFromHash() {
    // поддержка "#scans" и "#/scans"
    const raw = (window.location.hash || "").replace(/^#\/?/, "").trim();
    return normalizePage(raw);
  }

  function setHash(page) {
    // единый формат "#/page"
    const p = normalizePage(page);
    const next = `#/${p}`;
    if (window.location.hash !== next) window.location.hash = next;
  }

  async function navigate(page, opts = {}) {
    const { updateHash = true } = opts;

    const container = document.getElementById("pageContainer");
    if (!container) return;

    try {
      const pages = window.pages || {};
      const p = normalizePage(page);
      const pageModule = pages[p];

      if (!pageModule || typeof pageModule.render !== "function") {
        throw new Error(`pageModule.render is not a function (page=${p})`);
      }

      if (updateHash) setHash(p);

      setActiveNav(p);
      container.innerHTML = pageModule.render();

      if (typeof pageModule.init === "function") {
        await pageModule.init();
      }
    } catch (err) {
      console.error("Router error:", err);
      container.innerHTML = `
        <div class="page-wrapper">
          <div class="page-title">Ошибка загрузки страницы</div>
          <div style="color:#ff6b6b;margin-top:10px;">${String(err.message || err)}</div>
        </div>
      `;
      if (window.utils?.showNotification) {
        utils.showNotification("Ошибка загрузки страницы: " + String(err.message || err), "error");
      }
    }
  }

  // Восстанавливаем страницу при:
  // - открытии/обновлении (F5)
  // - изменении hash (вперед/назад в истории)
  window.addEventListener("load", () => {
    const rawHash = (window.location.hash || "").replace(/^#\/?/, "").trim();
    if (!rawHash) {
      try {
        history.replaceState(null, "", `#/${DEFAULT_PAGE}`);
      } catch (_) {}
    }
    const p = getPageFromHash();
    navigate(p, { updateHash: false });
  });

  window.addEventListener("hashchange", () => {
    const p = getPageFromHash();
    navigate(p, { updateHash: false });
  });

  window.router = { navigate };
})();
