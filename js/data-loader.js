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
    mode: "json",
    uploadedRaw: null,
    uploadedFormatted: null,
    uploadedMeta: null,
  };

  function safeStr(v) {
    return v === null || v === undefined ? "" : String(v);
  }

  function toNumber(v, fallback = 0) {
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  }

  function parseXml(text) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, "application/xml");
    const err = doc.querySelector("parsererror");
    if (err) {
      throw new Error("Некорректный XML-файл");
    }
    return doc;
  }

  function textOf(el, sel) {
    if (!el) return "";
    const n = sel ? el.querySelector(sel) : el;
    return n ? safeStr(n.textContent).trim() : "";
  }

  function directText(el) {
    if (!el) return "";
    let out = "";
    el.childNodes.forEach((n) => {
      if (n.nodeType === Node.TEXT_NODE) out += n.nodeValue || "";
    });
    return safeStr(out).trim();
  }

  function parsePortDetails(portText) {
    const port = safeStr(portText).trim();
    if (!port) return { port: "", port_num: null, proto: "" };
    const m = port.match(/^(\d+)\/(.+)$/);
    if (m) {
      return { port, port_num: Number(m[1]), proto: safeStr(m[2]).trim().toLowerCase() };
    }
    return { port, port_num: null, proto: "" };
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
      metadata: {
        generated_at: raw.generated_at || null,
        source: raw.source || "dataset",
        source_label: raw.source_label || "",
      },
    };
  }

  function parseOpenVasXmlReport(xmlText, fileName = "report.xml") {
    const doc = parseXml(xmlText);
    const reportNode =
      doc.querySelector("report > report") ||
      doc.querySelector("report report") ||
      doc.querySelector("report");

    if (!reportNode) {
      throw new Error("В XML не найден блок report");
    }

    const reportId = reportNode.getAttribute("id") || "";
    const generatedAt =
      textOf(reportNode, "timestamp") ||
      textOf(reportNode, "scan_start") ||
      textOf(reportNode, "scan_end") ||
      textOf(doc, "creation_time") ||
      new Date().toISOString();
    const taskName = textOf(reportNode, "task > name") || fileName;

    const resultNodes = Array.from(reportNode.querySelectorAll("results > result"));
    const assetsMap = new Map();
    const findings = resultNodes.map((r, idx) => {
      const hostEl = r.querySelector("host");
      const ip = directText(hostEl);
      const hostname = textOf(hostEl, "hostname");
      const assetId = safeStr(hostEl?.querySelector("asset")?.getAttribute("asset_id") || "").trim();
      const dedupKey = assetId || ip || hostname || `asset-${idx}`;
      const name = hostname || ip || dedupKey;

      if (!assetsMap.has(dedupKey)) {
        assetsMap.set(dedupKey, {
          asset_id: dedupKey,
          id: dedupKey,
          ip,
          ip_address: ip,
          hostname: hostname || name,
          name,
          asset_type: "host",
          status: "active",
          criticality: null,
          network_zone: "",
          owner_team: "",
        });
      }

      const nvt = r.querySelector("nvt");
      const portInfo = parsePortDetails(textOf(r, "port"));
      const cvssBase = toNumber(textOf(nvt, "cvss_base") || textOf(r, "severity") || 0, 0);
      const threat = textOf(r, "threat") || mapThreatToSeverity("", cvssBase);
      const cves = Array.from(r.querySelectorAll("refs > ref[type='cve']"))
        .map((n) => safeStr(n.getAttribute("id")).trim())
        .filter(Boolean);

      return {
        finding_id: r.getAttribute("id") || `${dedupKey}-${safeStr(textOf(nvt, "oid") || idx)}`,
        asset_id: dedupKey,
        ip,
        hostname: hostname || name,
        plugin_name: textOf(r, "name") || textOf(nvt, "name"),
        name: textOf(r, "name") || textOf(nvt, "name"),
        family: textOf(nvt, "family"),
        nvt_oid: safeStr(nvt?.getAttribute("oid") || "").trim(),
        cvss_base: cvssBase,
        threat,
        status: "open",
        detected_at: textOf(r, "modification_time") || textOf(r, "creation_time") || generatedAt,
        port: portInfo.port,
        port_num: portInfo.port_num,
        proto: portInfo.proto,
        description: textOf(r, "description"),
        solution: textOf(nvt, "solution"),
        cve: cves.join(","),
      };
    });

    const assets = Array.from(assetsMap.values());
    const scans = [
      {
        id: reportId || `xml-${Date.now()}`,
        name: taskName,
        status: textOf(reportNode, "scan_run_status") || "Done",
        started_at: textOf(reportNode, "scan_start") || generatedAt,
        generated_at: generatedAt,
        hosts_count: toNumber(textOf(reportNode, "hosts > count"), assets.length),
        vulns_count: toNumber(textOf(reportNode, "vulns > count"), findings.length),
      },
    ];

    return {
      generated_at: generatedAt,
      source: "xml",
      source_label: fileName,
      assets,
      findings,
      scans,
    };
  }

  function getCurrentFormattedData() {
    if (STORE.mode === "xml" && STORE.uploadedFormatted) return STORE.uploadedFormatted;
    return STORE.formatted;
  }

  async function loadDataset(forceReload = false) {
    if (STORE.mode === "xml" && STORE.uploadedFormatted) {
      api.data = STORE.uploadedFormatted;
      return true;
    }
    if (!forceReload && STORE.loaded && STORE.formatted) {
      api.data = STORE.formatted;
      return true;
    }

    const raw = await fetchDatasetJson();
    const formatted = normalizeDataset(raw);

    STORE.loaded = true;
    STORE.raw = raw;
    STORE.formatted = formatted;

    api.data = formatted;
    return true;
  }

  function _assets() {
    return getCurrentFormattedData()?.assets || [];
  }
  function _findings() {
    return getCurrentFormattedData()?.findings || [];
  }
  function _scans() {
    return getCurrentFormattedData()?.scans || [];
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

  function getSourceState() {
    return {
      mode: STORE.mode,
      hasXml: Boolean(STORE.uploadedFormatted),
      label:
        STORE.mode === "xml"
          ? STORE.uploadedMeta?.fileName || "XML отчёт"
          : "dataset.json",
    };
  }

  function setSourceMode(mode) {
    const m = safeStr(mode).toLowerCase() === "xml" ? "xml" : "json";
    if (m === "xml" && !STORE.uploadedFormatted) {
      throw new Error("Сначала загрузите XML-отчёт");
    }
    STORE.mode = m;
    api.data = getCurrentFormattedData() || null;
    return getSourceState();
  }

  async function loadXmlReportText(xmlText, fileName = "report.xml") {
    const raw = parseOpenVasXmlReport(xmlText, fileName);
    const formatted = normalizeDataset(raw);

    STORE.uploadedRaw = raw;
    STORE.uploadedFormatted = formatted;
    STORE.uploadedMeta = {
      fileName,
      loadedAt: new Date().toISOString(),
      findings: formatted.findings.length,
      assets: formatted.assets.length,
    };
    STORE.mode = "xml";
    api.data = formatted;
    return { ok: true, state: getSourceState(), meta: STORE.uploadedMeta };
  }

  const api = {
    CONFIG,
    data: null,

    loadDataset,
    loadApplicationData,
    loadXmlReportText,
    setSourceMode,
    getSourceState,

    getAssets,
    getFindings,
    getScans,
    getFindingsByAsset,
    getStats,
    normalizeFindingStatus,
  };

  window.dataLoader = api;
})();
