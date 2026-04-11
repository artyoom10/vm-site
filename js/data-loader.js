// js/data-loader.js
(() => {
  "use strict";

  const CONFIG = {
    DATASET_ENDPOINT: "/api/dataset.php",
    DEBUG: false,
  };

  const STORE = {
    loaded: false,
    raw: null,
    normalized: null,
    formatted: null,
  };

  function safeStr(v) {
    return v === null || v === undefined ? "" : String(v);
  }

  function toNumber(v, fallback = 0) {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  }

  /**
   * Канонический статус находки + отображение.
   * @returns {{ key: string, display: string, raw: string }}
   */
  function normalizeFindingStatus(raw) {
    const s0 = safeStr(raw).trim();
    const compact = s0.toLowerCase().replace(/\s+/g, "").replace(/-/g, "_");
    const underscored = s0.toLowerCase().replace(/\s+/g, "_").replace(/-/g, "_");

    const known = {
      open: { key: "open", display: "Open" },
      in_progress: { key: "in_progress", display: "In Progress" },
      inprogress: { key: "in_progress", display: "In Progress" },
      accepted_risk: { key: "accepted_risk", display: "Accepted Risk" },
      acceptedrisk: { key: "accepted_risk", display: "Accepted Risk" },
      resolved: { key: "resolved", display: "Resolved" },
      fixed: { key: "resolved", display: "Resolved" },
      closed: { key: "resolved", display: "Resolved" },
      false_positive: { key: "false_positive", display: "False Positive" },
      falsepositive: { key: "false_positive", display: "False Positive" },
      investigating: { key: "investigating", display: "Investigating" },
      triage: { key: "investigating", display: "Investigating" },
    };

    const hit = known[underscored] || known[compact];
    if (hit) {
      return { key: hit.key, display: hit.display, raw: s0 };
    }

    if (!s0) {
      return { key: "other", display: "Other", raw: s0 };
    }

    const title =
      s0.length > 1
        ? s0.charAt(0).toUpperCase() + s0.slice(1).toLowerCase()
        : s0.toUpperCase();
    return { key: "other", display: title, raw: s0 };
  }

  async function fetchDatasetJson() {
    const opts = { credentials: "same-origin", cache: "no-store" };
    let res = await fetch(CONFIG.DATASET_ENDPOINT, opts);

    if (res.status === 401) {
      const r2 = await fetch("/api/refresh.php", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
      });
      if (r2.ok) {
        res = await fetch(CONFIG.DATASET_ENDPOINT, opts);
      }
    }

    if (res.status === 401) {
      window.location.href = "/login.php";
      throw new Error("Unauthorized");
    }

    if (!res.ok) {
      throw new Error(`Failed to fetch dataset: ${res.status} ${res.statusText}`);
    }

    return res.json();
  }

  function mapThreatToSeverity(threat, cvssBase) {
    const t = safeStr(threat).toLowerCase();
    const cvss = toNumber(cvssBase, NaN);

    if (!Number.isNaN(cvss)) {
      if (cvss >= 9.0) return "Critical";
      if (cvss >= 7.0) return "High";
      if (cvss >= 4.0) return "Medium";
      if (cvss > 0.0) return "Low";
    }

    if (t === "high") return "High";
    if (t === "medium") return "Medium";
    if (t === "low") return "Low";
    return "Info";
  }

  function normalizeAssets(rawAssets = []) {
    return rawAssets.map((a) => {
      const id = safeStr(a.asset_id || a.id || a.assetId);
      const ip = safeStr(a.ip || a.ip_address || a.ipAddress);
      const hostname = safeStr(a.hostname || a.name);

      return {
        id,
        name: hostname || ip || id,
        hostname,
        ip_address: ip,
        asset_type: safeStr(a.asset_type || a.type || ""),
        status: safeStr(a.status || "unknown").toLowerCase(),
        criticality_num: Number.isFinite(Number(a.criticality)) ? Number(a.criticality) : null,
        network_zone: safeStr(a.network_zone || ""),
        owner_team: safeStr(a.owner_team || ""),
      };
    });
  }

  function buildAssetsIndex(assets) {
    const byId = new Map();
    const byIp = new Map();
    const byHostname = new Map();
    for (const a of assets) {
      if (a.id) byId.set(a.id, a);
      if (a.ip_address) byIp.set(a.ip_address, a);
      if (a.hostname) byHostname.set(a.hostname, a);
    }
    return { byId, byIp, byHostname };
  }

  function normalizeFindings(rawFindings = [], assetsIndex) {
    return rawFindings.map((f) => {
      const assetId = safeStr(f.asset_id);
      const ip = safeStr(f.ip);
      const hostname = safeStr(f.hostname);

      const asset =
        assetsIndex.byId.get(assetId) ||
        assetsIndex.byIp.get(ip) ||
        assetsIndex.byHostname.get(hostname);

      const id =
        safeStr(f.finding_id) ||
        `${assetId || "asset"}-${safeStr(f.nvt_oid || "nvt")}-${safeStr(f.port_num || f.port || "port")}`;

      const st = normalizeFindingStatus(f.status);

      const ownerTeam = safeStr(
        asset?.owner_team ||
          f.owner_team ||
          f.department ||
          (f.raw && (f.raw.owner_team || f.raw.department)) ||
          ""
      );

      return {
        id,
        asset_id: assetId,
        assetname: asset?.name || hostname || ip || assetId,
        affected_asset: asset?.name || hostname || ip || assetId,

        hostname,
        ip,
        owner_team: ownerTeam,
        department: ownerTeam,

        title: safeStr(f.plugin_name || f.name || f.nvt_oid || id),
        name: safeStr(f.plugin_name || f.name || ""),
        pluginname: safeStr(f.plugin_name || ""),
        family: safeStr(f.family || ""),
        nvt_oid: safeStr(f.nvt_oid || ""),

        severity: mapThreatToSeverity(f.threat, f.cvss_base).toLowerCase(),

        status_raw: st.raw,
        status_key: st.key,
        status_display: st.display,
        status: st.key,

        cvss_score: toNumber(f.cvss_base, 0),
        cvssbase: toNumber(f.cvss_base, 0),
        detectedat: safeStr(f.detected_at || ""),
        createdat: safeStr(f.detected_at || ""),
        raw: f,
      };
    });
  }

  function normalizeDataset(raw) {
    const assets = normalizeAssets(Array.isArray(raw.assets) ? raw.assets : []);
    const assetsIndex = buildAssetsIndex(assets);
    const findings = normalizeFindings(Array.isArray(raw.findings) ? raw.findings : [], assetsIndex);
    const scans = Array.isArray(raw.scans) ? raw.scans : [];

    return {
      assets,
      findings,
      scans,
      metadata: { generated_at: raw.generated_at || null, source: raw.source || "dataset" },
    };
  }

  async function loadDataset(forceReload = false) {
    if (!forceReload && STORE.loaded && STORE.formatted) return true;

    const raw = await fetchDatasetJson();
    const formatted = normalizeDataset(raw);

    STORE.loaded = true;
    STORE.raw = raw;
    STORE.formatted = formatted;

    api.data = formatted;
    return true;
  }

  function _assets() {
    return STORE.formatted?.assets || [];
  }
  function _findings() {
    return STORE.formatted?.findings || [];
  }
  function _scans() {
    return STORE.formatted?.scans || [];
  }

  function _wrapData(arr, opts) {
    const limit = opts && typeof opts.limit === "number" ? opts.limit : null;
    const out = limit ? arr.slice(0, limit) : arr;
    return Promise.resolve({ data: out, error: null });
  }

  function getAssets(opts) {
    if (opts && typeof opts === "object") return _wrapData(_assets(), opts);
    return _assets();
  }

  function getFindings(opts) {
    if (opts && typeof opts === "object") return _wrapData(_findings(), opts);
    return _findings();
  }

  function getScans(opts) {
    if (opts && typeof opts === "object") return _wrapData(_scans(), opts);
    return _scans();
  }

  function getFindingsByAsset(opts) {
    const all = _findings();

    const assetKey = safeStr(opts?.assetId || opts?.asset || "").toLowerCase();
    let filtered = all;

    if (assetKey) {
      filtered = all.filter((f) => {
        return (
          safeStr(f.asset_id).toLowerCase() === assetKey ||
          safeStr(f.hostname).toLowerCase() === assetKey ||
          safeStr(f.ip).toLowerCase() === assetKey ||
          safeStr(f.assetname).toLowerCase() === assetKey
        );
      });
    }

    if (opts && typeof opts === "object") return _wrapData(filtered, opts);
    return filtered;
  }

  function getStats() {
    const assets = _assets();
    const findings = _findings();

    const totalAssets = assets.length;
    const totalFindings = findings.length;
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const resolvedCount = findings.filter((f) => f.status_key === "resolved").length;
    const openCount = findings.filter((f) => f.status_key === "open").length;

    return { totalAssets, totalFindings, criticalCount, resolvedCount, openCount };
  }

  async function loadApplicationData(forceReload = false) {
    await loadDataset(forceReload);
    return api.data;
  }

  const api = {
    CONFIG,
    data: null,

    loadDataset,
    loadApplicationData,

    getAssets,
    getFindings,
    getScans,
    getFindingsByAsset,
    getStats,
    normalizeFindingStatus,
  };

  window.dataLoader = api;
})();
