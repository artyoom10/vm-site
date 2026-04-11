// js/utils.js
// Утилиты общего назначения

const utils = {
  /**
   * Форматирование даты
   * @param {string|Date} date - дата
   * @param {string} format - формат (en-US, ru-RU)
   * @returns {string}
   */
  formatDate(date, format = 'ru-RU') {
    const d = new Date(date);
    return d.toLocaleDateString(format, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  },

  /**
   * Форматирование времени относительно сейчас (1м назад, 2ч назад и т.д.)
   * @param {string|Date} date - дата
   * @returns {string}
   */
  formatRelativeTime(date) {
    const d = new Date(date);
    const now = new Date();
    const diffMs = now - d;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 60) return `${diffSecs}с назад`;
    if (diffMins < 60) return `${diffMins}м назад`;
    if (diffHours < 24) return `${diffHours}ч назад`;
    if (diffDays < 7) return `${diffDays}д назад`;

    return this.formatDate(date);
  },

  /**
   * CSS класс для severity
   * @param {string} severity - critical, high, medium, low, info
   * @returns {string}
   */
  getSeverityClass(severity) {
    const severityMap = {
      critical: 'severity-critical',
      high: 'severity-high',
      medium: 'severity-medium',
      low: 'severity-low',
      info: 'severity-info',
    };
    return severityMap[severity] || 'severity-info';
  },

  /**
   * Красивая severity иконка
   * @param {string} severity - critical, high, medium, low, info
   * @returns {string} - emoji или иконка
   */
  getSeverityIcon(severity) {
    const icons = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: '🔵',
    };
    return icons[severity] || '⚪';
  },

  /**
   * CSS класс для статуса
   * @param {string} status - open, investigating, resolved, false_positive
   * @returns {string}
   */
  getStatusClass(status) {
    const statusMap = {
      open: 'status-open',
      in_progress: 'status-in-progress',
      accepted_risk: 'status-accepted-risk',
      investigating: 'status-investigating',
      resolved: 'status-resolved',
      false_positive: 'status-false-positive',
      other: 'status-other',
    };
    return statusMap[status] || 'status-other';
  },

  /**
   * Красивый текст статуса
   * @param {string} status - open, investigating, resolved, false_positive
   * @returns {string}
   */
  getStatusText(status) {
    const textMap = {
      open: 'Открыто',
      in_progress: 'В работе',
      accepted_risk: 'Риск принят',
      investigating: 'Расследование',
      resolved: 'Решено',
      false_positive: 'Ложный',
      other: 'Прочее',
    };
    return textMap[status] || status;
  },

  /**
   * Валидация email
   * @param {string} email
   * @returns {boolean}
   */
  isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  },

  /**
   * Валидация IP адреса
   * @param {string} ip
   * @returns {boolean}
   */
  isValidIP(ip) {
    const re = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!re.test(ip)) return false;

    const parts = ip.split('.');
    return parts.every((part) => {
      const num = parseInt(part);
      return num >= 0 && num <= 255;
    });
  },

  /**
   * Экранирование HTML спецсимволов
   * @param {string} text
   * @returns {string}
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  /**
   * Копирование в буфер обмена
   * @param {string} text - текст для копирования
   */
  copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      console.log('Copied to clipboard:', text);
    });
  },

  /**
   * Показать уведомление (toast)
   * @param {string} message - текст
   * @param {string} type - success, error, info, warning
   * @param {number} duration - длительность в мс (0 = не скрывать)
   */
  showNotification(message, type = 'info', duration = 3000) {
    const toastId = `toast-${Date.now()}`;
    const toast = document.createElement('div');
    toast.id = toastId;
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span>${utils.escapeHtml(message)}</span>
      <button onclick="document.getElementById('${toastId}').remove()" style="background: none; border: none; color: inherit; cursor: pointer; margin-left: 10px;">✕</button>
    `;

    // Стили для тоста (инлайн)
    toast.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #333;
      color: #fff;
      padding: 12px 16px;
      border-radius: 6px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2);
      display: flex;
      align-items: center;
      justify-content: space-between;
      z-index: 9999;
      animation: slideIn 0.3s ease-out;
    `;

    if (type === 'success') {
      toast.style.backgroundColor = '#4CAF50';
    } else if (type === 'error') {
      toast.style.backgroundColor = '#f44336';
    } else if (type === 'warning') {
      toast.style.backgroundColor = '#ff9800';
    }

    document.body.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => {
        toast.remove();
      }, duration);
    }
  },

  /**
   * Генерация уникального ID
   * @returns {string}
   */
  generateId() {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  },

  /**
   * Сортировка массива объектов
   * @param {Array} arr - массив
   * @param {string} key - поле для сортировки
   * @param {string} order - asc или desc
   * @returns {Array}
   */
  sortArray(arr, key, order = 'asc') {
    return arr.sort((a, b) => {
      if (a[key] < b[key]) return order === 'asc' ? -1 : 1;
      if (a[key] > b[key]) return order === 'asc' ? 1 : -1;
      return 0;
    });
  },

  /**
   * Группировка массива объектов
   * @param {Array} arr - массив
   * @param {string} key - поле для группировки
   * @returns {Object}
   */
  groupArray(arr, key) {
    return arr.reduce((result, item) => {
      const group = item[key];
      if (!result[group]) result[group] = [];
      result[group].push(item);
      return result;
    }, {});
  },

  /**
   * Дебаунс функции
   * @param {Function} func - функция
   * @param {number} delay - задержка в мс
   * @returns {Function}
   */
  debounce(func, delay = 300) {
    let timeoutId;
    return function (...args) {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func(...args), delay);
    };
  },

  /**
   * Утилита для построения URL query параметров
   * @param {Object} params - объект параметров
   * @returns {string}
   */
  buildQueryString(params) {
    return Object.entries(params)
      .filter(([, value]) => value !== null && value !== undefined && value !== '')
      .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
      .join('&');
  },
};

// Экспортируем в window
window.utils = utils;

/**
 * Общий tooltip для диаграмм (дашборд, карточка актива и т.д.)
 */
(() => {
  function pct(val, total) {
    if (!total) return 0;
    return Math.round((Number(val || 0) / total) * 100);
  }

  function ensureEl() {
    let el = document.getElementById('vmGlobalTooltip');
    if (el) return el;
    el = document.createElement('div');
    el.id = 'vmGlobalTooltip';
    el.style.cssText = [
      'position:fixed',
      'display:none',
      'pointer-events:none',
      'min-width:220px',
      'max-width:300px',
      'padding:10px 12px',
      'border-radius:14px',
      'background:rgba(18,18,18,.92)',
      'color:#fff',
      'border:1px solid rgba(255,255,255,.12)',
      'box-shadow:0 14px 34px rgba(0,0,0,.42)',
      'backdrop-filter:blur(8px)',
      '-webkit-backdrop-filter:blur(8px)',
      'z-index:50000',
      'font-family:ui-sans-serif,"Segoe UI",system-ui,-apple-system,sans-serif',
    ].join(';');
    el.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span id="vmgttDot" style="width:10px;height:10px;border-radius:50%;background:#999;flex-shrink:0;"></span>
          <div id="vmgttTitle" style="font-weight:700;font-size:13px;letter-spacing:.01em;">—</div>
        </div>
        <div id="vmgttPct" style="opacity:.88;font-weight:700;font-size:12px;font-variant-numeric:tabular-nums;">0%</div>
      </div>
      <div style="margin-top:8px;display:flex;align-items:baseline;gap:10px;">
        <div id="vmgttValue" style="font-weight:800;font-size:26px;line-height:1;font-variant-numeric:tabular-nums;">0</div>
        <div id="vmgttSub" style="opacity:.82;font-weight:600;font-size:12px;letter-spacing:.02em;">уязвимостей</div>
      </div>`;
    document.body.appendChild(el);
    return el;
  }

  function showAt({ x, y, title, value, percent, color, subtitle }) {
    const tooltip = ensureEl();
    const dot = tooltip.querySelector('#vmgttDot');
    const ttTitle = tooltip.querySelector('#vmgttTitle');
    const ttValue = tooltip.querySelector('#vmgttValue');
    const ttPct = tooltip.querySelector('#vmgttPct');
    const ttSub = tooltip.querySelector('#vmgttSub');
    if (dot) dot.style.background = color || '#999';
    if (ttTitle) ttTitle.textContent = String(title ?? '—');
    if (ttValue) ttValue.textContent = String(Number(value ?? 0));
    if (ttPct) ttPct.textContent = `${Number(percent ?? 0)}%`;
    if (ttSub) ttSub.textContent = subtitle || 'уязвимостей';
    tooltip.style.display = 'block';
    const rect = tooltip.getBoundingClientRect();
    const tw = rect.width || 260;
    const th = rect.height || 90;
    const pad = 12;
    const offset = 14;
    let left = x + offset;
    let top = y + offset;
    if (left + tw + pad > window.innerWidth) left = x - tw - offset;
    if (top + th + pad > window.innerHeight) top = y - th - offset;
    left = Math.max(pad, Math.min(window.innerWidth - tw - pad, left));
    top = Math.max(pad, Math.min(window.innerHeight - th - pad, top));
    tooltip.style.left = `${left}px`;
    tooltip.style.top = `${top}px`;
  }

  function hide() {
    const tooltip = document.getElementById('vmGlobalTooltip');
    if (tooltip) tooltip.style.display = 'none';
  }

  window.vmTooltip = { ensure: ensureEl, showAt, hide, pct };
})();