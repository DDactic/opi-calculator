/**
 * OPI Calculator - Open Protection Index scoring engine (JavaScript)
 *
 * Implements the OPI v1.1.0 specification for measuring DDoS resilience.
 * See: https://github.com/ddactic/opi-calculator
 *
 * @example
 * const { calculateOPI } = require('./opi-calculator');
 *
 * const result = calculateOPI({
 *   assets: [
 *     { fqdn: 'app.example.com', cdn: true, waf: true, originHidden: true },
 *     { fqdn: 'api.example.com', cdn: true, waf: false, originHidden: false },
 *     { fqdn: 'mail.example.com', cdn: false, waf: false, originHidden: false },
 *   ],
 *   cdnQuality: 'standard',
 * });
 * console.log(`OPI: ${result.score}/100 (Grade ${result.grade})`);
 */

// OPI v1.1.0 component weights (Section 3.1)
const WEIGHTS = {
  defenseCoverage: 0.20,
  l7Attack: 0.25,
  l3l4Attack: 0.15,
  protocol: 0.15,
  operational: 0.15,
  evasion: 0.10,
};

// Grade scale (Section 3.2)
const GRADE_SCALE = [
  [90, 'A', 'Excellent'],
  [80, 'B', 'Good'],
  [70, 'C', 'Adequate'],
  [60, 'D', 'Poor'],
  [0, 'F', 'Critical'],
];

// Vendor automation tiers
const VENDOR_AUTOMATION_TIERS = {
  cloudflare: 100, aws: 100, cloudfront: 100, amazon: 100,
  azure: 100, microsoft: 100, google: 100, gcp: 100,
  radware: 80, arbor: 75, netscout: 75, neustar: 75,
  fastly: 60, imperva: 60, incapsula: 60, gcore: 60, sucuri: 60,
  akamai: 20, prolexic: 20, f5: 20,
};

// Scrubbing center quality tiers
const SCRUBBING_QUALITY = {
  radware: 90, imperva: 75, incapsula: 75, neustar: 72,
  akamai: 70, prolexic: 70, netscout: 65, arbor: 60, f5: 55,
};

function gradeFromScore(score) {
  for (const [threshold, grade, classification] of GRADE_SCALE) {
    if (score >= threshold) return { grade, classification };
  }
  return { grade: 'F', classification: 'Critical' };
}

function defenseCoverageScore(assets) {
  const total = Math.max(assets.length, 1);

  const cdnCount = assets.filter(a => a.cdn).length;
  const cdn = Math.round((cdnCount / total) * 100);

  const wafCount = assets.filter(a => a.waf).length;
  const rlCount = assets.filter(a => a.rateLimiting).length;
  const waf = wafCount > 0 ? Math.round((wafCount / total) * 100)
    : rlCount > 0 ? 50 : 0;

  let exposed = 0;
  let tunnelCount = 0;
  for (const a of assets) {
    if (a.hasTunnel) { tunnelCount++; continue; }
    if (a.cdn && !a.originHidden) exposed++;
    else if (!a.cdn) exposed++;
  }
  const origin = Math.round((Math.max(0, cdnCount - exposed) / total) * 100);
  const rateLimit = Math.round((rlCount / total) * 100);

  // Protection automation
  const vendorScores = [];
  let hasScrubbing = false;
  let scrubbingQuality = 0;
  for (const a of assets) {
    const vendor = (a.vendor || '').toLowerCase();
    const scrub = (a.scrubbing || '').toLowerCase();
    for (const [v, tier] of Object.entries(VENDOR_AUTOMATION_TIERS)) {
      if (vendor.includes(v) || scrub.includes(v)) vendorScores.push(tier);
    }
    for (const [sv, quality] of Object.entries(SCRUBBING_QUALITY)) {
      if (scrub.includes(sv)) {
        hasScrubbing = true;
        scrubbingQuality = Math.max(scrubbingQuality, quality);
      }
    }
  }

  let automation = 0;
  if (vendorScores.length > 0) {
    automation = Math.round(vendorScores.reduce((a, b) => a + b, 0) / vendorScores.length);
    if (hasScrubbing) automation = Math.min(100, automation + 10);
  }

  const score = Math.round(
    cdn * 0.25 + waf * 0.25 + origin * 0.20 + rateLimit * 0.15 + automation * 0.15
  );

  return {
    score, cdnDeployment: cdn, wafDeployment: waf,
    originProtection: origin, rateLimiting: rateLimit,
    protectionAutomation: automation, hasScrubbing, scrubbingQuality, tunnelAssets: tunnelCount,
  };
}

function l7ResilienceScore({ cdnQuality = 'none', cdnCoverage = 0, attackResults = null } = {}) {
  if (attackResults) {
    const weights = {
      httpFlood: 0.30, slowloris: 0.20, resourceExhaustion: 0.20,
      cacheBypass: 0.15, apiAbuse: 0.15,
    };
    let wSum = 0, tWeight = 0;
    const perAttack = {};
    for (const [attack, weight] of Object.entries(weights)) {
      if (attackResults[attack]) {
        const r = attackResults[attack];
        const s = Math.round(r.availability * 0.50 + r.latencyFactor * 0.30 + (1 - r.errorRate) * 100 * 0.20);
        perAttack[attack] = s;
        wSum += s * weight;
        tWeight += weight;
      }
    }
    return { score: Math.round(wSum / Math.max(tWeight, 0.01)), source: 'measured', perAttack };
  }

  const cov = Math.max(0, Math.min(1, cdnCoverage));
  const baseMap = { enterprise: 80, standard: 55, basic: 40, none: 10 };
  const base = baseMap[cdnQuality] || 10;
  return { score: Math.round(base * cov + 10 * (1 - cov)), source: 'estimated' };
}

/**
 * Calculate L7 DDoS-relevant penalty from passive recon findings (Section 4.2.5, v1.1).
 * @param {Array} l7Findings - Array of {findingType: string} objects from L7 recon.
 * @returns {{penalty: number, applied: Array, source: string}}
 */
function l7AttackSurfacePenalty(l7Findings) {
  if (!l7Findings || l7Findings.length === 0) return { penalty: 0, applied: [], source: 'no_l7_data' };
  const counts = {};
  l7Findings.forEach(f => { const t = f.findingType || f.finding_type || ''; counts[t] = (counts[t] || 0) + 1; });

  let penalty = 0;
  const applied = [];

  if (counts.graphql_introspection > 0) { penalty += 12; applied.push({ finding: 'graphql_introspection', penalty: 12 }); }
  else if ((counts.graphql_endpoint || 0) > 5) { penalty += 8; applied.push({ finding: 'graphql_endpoints_many', penalty: 8 }); }
  else if ((counts.graphql_endpoint || 0) > 0) { penalty += 4; applied.push({ finding: 'graphql_endpoints', penalty: 4 }); }

  if (counts.wp_xmlrpc > 0) { penalty += 6; applied.push({ finding: 'wp_xmlrpc', penalty: 6 }); }

  const hasRl = (counts.rate_limit_config || 0) > 0;
  const loginCnt = (counts.login_endpoint || 0) + (counts.login_detected || 0);
  if (!hasRl && loginCnt > 3) { penalty += 8; applied.push({ finding: 'no_rate_limit_with_logins', penalty: 8 }); }

  const apiCnt = (counts.api_endpoint_discovered || 0) + (counts.graphql_endpoint || 0);
  if (apiCnt > 20) { penalty += 6; applied.push({ finding: 'large_api_surface', penalty: 6 }); }
  else if (apiCnt > 5) { penalty += 3; applied.push({ finding: 'api_surface', penalty: 3 }); }

  return { penalty, applied, source: 'l7_recon' };
}

function l3l4ResilienceScore({
  cdnCoverage = 0, hasCdn = false, exposedOrigins = 0,
  scrubbingVendor = null, pipelineGbps = null, ispTier = null,
} = {}) {
  const cov = Math.max(0, Math.min(1, cdnCoverage));
  let hasScrubbing = false, scrubbingQuality = 0;

  if (scrubbingVendor) {
    const sv = scrubbingVendor.toLowerCase();
    for (const [vendor, quality] of Object.entries(SCRUBBING_QUALITY)) {
      if (sv.includes(vendor)) { hasScrubbing = true; scrubbingQuality = Math.max(scrubbingQuality, quality); }
    }
  }

  let pipelineBase = null;
  if (pipelineGbps !== null) {
    if (pipelineGbps < 1) pipelineBase = 20;
    else if (pipelineGbps < 10) pipelineBase = 40;
    else if (pipelineGbps < 100) pipelineBase = 55;
    else if (pipelineGbps < 1000) pipelineBase = 70;
    else pipelineBase = 85;
  }

  const ispScores = { none: 0, basic: 25, standard: 40, premium: 55, enterprise: 70 };
  const ispScore = ispTier ? (ispScores[ispTier.toLowerCase()] || 0) : 0;

  let base;
  if (hasScrubbing) {
    base = scrubbingQuality - (exposedOrigins > 0 ? 15 : 0);
    if (ispScore > 0) base = Math.min(100, base + Math.round(ispScore * 0.2));
    if (pipelineBase !== null && pipelineBase < base) base = Math.round((base + pipelineBase) / 2);
  } else if (ispScore > 0) {
    base = ispScore - (exposedOrigins > 0 ? 10 : 0);
    if (pipelineBase !== null && pipelineBase < base) base = Math.round((base + pipelineBase) / 2);
  } else if (pipelineBase !== null) {
    base = pipelineBase - (exposedOrigins > 0 ? 15 : 0);
  } else {
    base = exposedOrigins === 0 ? 85 : 50;
  }

  base = Math.max(20, base);
  const score = hasCdn ? Math.round(base * cov + 20 * (1 - cov)) : base;
  return { score, source: 'estimated', hasScrubbing, scrubbingQuality };
}

function protocolResilienceScore({ cdnQuality = 'none', cdnCoverage = 0, hasCdn = false } = {}) {
  const cov = Math.max(0, Math.min(1, cdnCoverage));
  const base = ['enterprise', 'standard'].includes(cdnQuality) ? 70 : 30;
  const score = hasCdn ? Math.round(base * cov + 50 * (1 - cov)) : 50;
  return { score, source: 'estimated' };
}

function operationalResilienceScore({ cdnQuality = 'none', cdnCoverage = 0, cdnScore = 0, hasCdn = false } = {}) {
  const cov = Math.max(0, Math.min(1, cdnCoverage));
  let score;
  if (cdnScore > 80) score = Math.round(75 * cov + 30 * (1 - cov));
  else if (hasCdn) score = Math.round(50 * cov + 30 * (1 - cov));
  else score = 30;
  return { score, source: 'estimated' };
}

function evasionResistanceScore({ cdnQuality = 'none', cdnCoverage = 0, hasCdn = false } = {}) {
  const cov = Math.max(0, Math.min(1, cdnCoverage));
  let score;
  if (cdnQuality === 'enterprise') score = 60;
  else if (hasCdn) score = Math.round(30 * cov + 10 * (1 - cov));
  else score = 10;
  return { score, source: 'estimated' };
}

/**
 * Calculate complete OPI score.
 * @param {Object} options
 * @param {Array} options.assets - Asset inventory
 * @param {string} [options.cdnQuality='none'] - CDN quality tier
 * @param {string} [options.scrubbingVendor] - Scrubbing vendor name
 * @param {number} [options.pipelineGbps] - Upstream link capacity
 * @param {string} [options.ispTier] - ISP DDoS protection tier
 * @returns {Object} OPI result with score, grade, and component breakdown
 */
function calculateOPI({
  assets, cdnQuality = 'none',
  scrubbingVendor = null, pipelineGbps = null, ispTier = null,
  l7Findings = null,
} = {}) {
  const total = Math.max(assets.length, 1);
  const cdnCount = assets.filter(a => a.cdn).length;
  const cdnCov = cdnCount / total;
  const hasCdn = cdnQuality !== 'none' || cdnCount > 0;
  const exposed = assets.filter(a => a.cdn && !a.originHidden).length
    + assets.filter(a => !a.cdn && !a.hasTunnel).length;

  const dc = defenseCoverageScore(assets);
  const l7 = l7ResilienceScore({ cdnQuality, cdnCoverage: cdnCov });

  // L7 Attack Surface penalties (Section 4.2.5, v1.1)
  const l7Surface = l7AttackSurfacePenalty(l7Findings);
  if (l7Surface.penalty > 0 && l7.source === 'estimated') {
    l7.score = Math.max(0, l7.score - l7Surface.penalty);
    l7.l7SurfacePenalty = l7Surface;
  }

  const l3l4 = l3l4ResilienceScore({
    cdnCoverage: cdnCov, hasCdn, exposedOrigins: exposed,
    scrubbingVendor, pipelineGbps, ispTier,
  });
  const proto = protocolResilienceScore({ cdnQuality, cdnCoverage: cdnCov, hasCdn });
  const ops = operationalResilienceScore({
    cdnQuality, cdnCoverage: cdnCov, cdnScore: dc.cdnDeployment, hasCdn,
  });
  const evasion = evasionResistanceScore({ cdnQuality, cdnCoverage: cdnCov, hasCdn });

  const score = Math.round(
    dc.score * WEIGHTS.defenseCoverage +
    l7.score * WEIGHTS.l7Attack +
    l3l4.score * WEIGHTS.l3l4Attack +
    proto.score * WEIGHTS.protocol +
    ops.score * WEIGHTS.operational +
    evasion.score * WEIGHTS.evasion
  );

  const { grade, classification } = gradeFromScore(score);

  // Assessment tier (Section 3.4)
  const hasL7Recon = l7Findings && l7Findings.length > 0;
  const tier = 'passive'; // JS calculator is passive-only; active testing uses Python backend

  return {
    score, grade, classification,
    tier: hasL7Recon ? 'estimated' : tier,
    components: {
      defenseCoverage: dc, l7Attack: l7, l3l4Attack: l3l4,
      protocol: proto, operational: ops, evasion,
    },
    weights: WEIGHTS,
    assetCount: assets.length,
    version: '1.1.0',
  };
}

/**
 * Normalize OPI by attack intensity (Section 6.3).
 */
function normalizedOPI(rawScore, fleetRps, fleetCount = 1) {
  const intensity = Math.log10(1 + fleetRps);
  const scale = Math.log10(1 + fleetCount);
  return Math.round(rawScore * (1 + intensity * 0.1 + scale * 0.05) * 10) / 10;
}

// Node.js / CommonJS export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    calculateOPI, defenseCoverageScore, l7ResilienceScore, l7AttackSurfacePenalty,
    l3l4ResilienceScore, protocolResilienceScore, operationalResilienceScore,
    evasionResistanceScore, gradeFromScore, normalizedOPI,
    WEIGHTS, GRADE_SCALE, VENDOR_AUTOMATION_TIERS, SCRUBBING_QUALITY,
  };
}

// ESM / browser export
if (typeof globalThis !== 'undefined') {
  globalThis.OPICalculator = {
    calculateOPI, defenseCoverageScore, gradeFromScore, normalizedOPI,
    WEIGHTS, GRADE_SCALE,
  };
}
