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
    sourceFlags: { json: true, xml: false },
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

  function mergeDatasets(parts) {
    const datasets = (parts || []).filter(Boolean);
    if (!datasets.length) {
      return { assets: [], findings: [], scans: [], metadata: { generated_at: null, source: "empty" } };
    }
    if (datasets.length === 1) return datasets[0];

    const assets = [];
    const findings = [];
    const scans = [];
    let latest = "";
    const labels = [];

    datasets.forEach((d) => {
      assets.push(...(Array.isArray(d.assets) ? d.assets : []));
      findings.push(...(Array.isArray(d.findings) ? d.findings : []));
      scans.push(...(Array.isArray(d.scans) ? d.scans : []));

      const g = safeStr(d.metadata?.generated_at || "").trim();
      if (g && (!latest || g > latest)) latest = g;
      const l = safeStr(d.metadata?.source_label || "").trim();
      if (l) labels.push(l);
    });

    return {
      assets,
      findings,
      scans,
      metadata: {
        generated_at: latest || null,
        source: "mixed",
        source_label: labels.join(" + "),
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
    const gmpVersion = textOf(reportNode, "gmp > version");
    const reportFormat = textOf(reportNode, "report_format > name") || "XML";
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
      _meta: {
        report_id: reportId,
        task_name: taskName,
        scan_status: textOf(reportNode, "scan_run_status") || "Done",
        scan_start: textOf(reportNode, "scan_start") || generatedAt,
        report_format: reportFormat,
        scanner: gmpVersion ? `OpenVAS/GMP ${gmpVersion}` : "OpenVAS XML",
      },
    };
  }

  function getCurrentFormattedData() {
    const includeJson = Boolean(STORE.sourceFlags.json);
    const includeXml = Boolean(STORE.sourceFlags.xml && STORE.uploadedFormatted);

    if (includeJson && includeXml) return mergeDatasets([STORE.formatted, STORE.uploadedFormatted]);
    if (includeXml) return STORE.uploadedFormatted;
    if (includeJson) return STORE.formatted;
    return STORE.formatted || STORE.uploadedFormatted || null;
  }

  async function loadDataset(forceReload = false) {
    if (!forceReload && STORE.loaded && STORE.formatted) {
      api.data = getCurrentFormattedData();
      return true;
    }

    const raw = await fetchDatasetJson();
    const formatted = normalizeDataset(raw);

    STORE.loaded = true;
    STORE.raw = raw;
    STORE.formatted = formatted;

    api.data = getCurrentFormattedData();
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
      mode:
        STORE.sourceFlags.json && STORE.sourceFlags.xml
          ? "mixed"
          : STORE.sourceFlags.xml
            ? "xml"
            : "json",
      enabled: { ...STORE.sourceFlags },
      hasXml: Boolean(STORE.uploadedFormatted),
      label: STORE.uploadedMeta?.fileName || "",
      jsonMeta: STORE.formatted
        ? {
            generatedAt: STORE.formatted.metadata?.generated_at || null,
            assets: (STORE.formatted.assets || []).length,
            findings: (STORE.formatted.findings || []).length,
            scans: (STORE.formatted.scans || []).length,
          }
        : null,
      xmlMeta: STORE.uploadedMeta || null,
    };
  }

  function setSourceEnabled(source, enabled) {
    const src = safeStr(source).toLowerCase() === "xml" ? "xml" : "json";
    if (src === "xml" && enabled && !STORE.uploadedFormatted) {
      throw new Error("Сначала загрузите XML-отчёт");
    }
    STORE.sourceFlags[src] = Boolean(enabled);
    if (!STORE.sourceFlags.json && !STORE.sourceFlags.xml) {
      STORE.sourceFlags.json = true;
    }
    api.data = getCurrentFormattedData() || null;
    return getSourceState();
  }

  function setSourceMode(mode) {
    const m = safeStr(mode).toLowerCase() === "xml" ? "xml" : "json";
    STORE.sourceFlags.json = m === "json";
    STORE.sourceFlags.xml = m === "xml";
    return setSourceEnabled(m, true);
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
      scans: formatted.scans.length,
      generatedAt: raw.generated_at || null,
      scanner: raw._meta?.scanner || "OpenVAS XML",
      reportFormat: raw._meta?.report_format || "XML",
      taskName: raw._meta?.task_name || fileName,
      scanStatus: raw._meta?.scan_status || "Done",
      scanStart: raw._meta?.scan_start || raw.generated_at || null,
    };
    STORE.sourceFlags.xml = true;
    api.data = getCurrentFormattedData() || formatted;
    return { ok: true, state: getSourceState(), meta: STORE.uploadedMeta };
  }

  const api = {
    CONFIG,
    data: null,

    loadDataset,
    loadApplicationData,
    loadXmlReportText,
    setSourceEnabled,
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
