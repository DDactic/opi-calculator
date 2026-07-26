/**
 * OPI Calculator - Open Protection Index scoring engine (JavaScript)
 *
 * Implements the OPI v1.4.0 specification for measuring DDoS resilience.
 * See: https://github.com/ddactic/opi-calculator
 *
 * Changelog v1.5.0:
 *  - Rate limit counting architecture penalty (Section 4.2.6):
 *    CDN vendors that use per-PoP/per-edge/per-server counting are bypasable via
 *    geographic IP distribution even when rate limiting IS configured. Penalties
 *    applied when rate limiting is detected AND a cloud CDN vendor is identified.
 *    Azure Front Door (per-server, -8), Cloudflare/Akamai/GCP (per-PoP/region, -5),
 *    Imperva (-4), Fastly/CloudFront/AWS WAF (hybrid/propagation-delay, -3).
 *    Centralized vendors (Radware, Arbor, Netscout): no penalty.
 *    Source: DDactic CDN_RATE_LIMIT_COUNTING_RESEARCH.md
 *
 * Changelog v1.4.0 (synced with backend compute_opi_scores):
 *  - Config-aware WAF scoring via optional vendorConfigs parameter
 *  - On-prem WAF vendor_class credits (ddos_appliance, security_waf, load_balancer, cloud_waf)
 *  - On-prem L3/L4 stacking with cloud scrubbing and ISP tier
 *  - ISP tier stacking bonuses (20% with scrubbing, 30% with on-prem)
 *  - L7 base cap for security_waf-only (no CDN, no ddos_appliance)
 *  - Scaling architecture bonus in operational resilience
 *  - AI SLD exclusion for third-party asset filtering
 *  - Hardening potential metric
 *  - Origin leak via DNS penalty (-20 to origin protection)
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

// OPI v1.4.0 component weights (Section 3.1)
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
  cloudflare: 95, radware: 90, aws: 85, shield: 85,
  imperva: 75, incapsula: 75, neustar: 72, vercara: 72,
  akamai: 70, prolexic: 70, netscout: 65, arbor: 60, f5: 55,
};

// Rate limit counting architecture penalty (Section 4.2.6, v1.5)
// Penalty applied when rate limiting IS present but the vendor's counting architecture
// is per-PoP/per-edge/per-server — bypasable via geographic IP distribution.
// Keyed by substring match against the lowercased cdn_provider / vendor field.
// Centralized vendors (radware, arbor, netscout) are absent = 0 penalty.
const RL_COUNTING_ARCH_PENALTY = {
  'azure front door': 8,  // per-server: same client hits different servers via LB, loosest granularity
  'cloudflare':       5,  // per-PoP: independent counters per DC, bypasable with geographic fleet
  'akamai':           5,  // per-edge: 1-3s sync delay, burst-within-window bypass
  'imperva':          4,  // per-PoP (undocumented sync, assumed same class as Cloudflare)
  'incapsula':        4,
  'google cloud cdn': 5,  // per-region: N deployment regions = N × configured threshold
  'gcp':              5,
  'fastly':           3,  // hybrid local+global (30s aggregation, effective threshold ~2×)
  'cloudfront':       3,  // global but ~30s propagation delay before enforcement
  'aws':              3,  // same as CloudFront
};

// On-prem WAF vendor_class base credits (fraction of a full cloud WAF)
const VENDOR_CLASS_WAF_CREDITS = {
  cloud_waf: 1.0,
  ddos_appliance: 0.7,
  security_waf: 0.4,
  load_balancer: 0.4,
  unknown: 0.4,
};

// On-prem L3/L4 bonus by vendor_class
const ONPREM_L3L4_BONUS = {
  ddos_appliance: 45,
  security_waf: 15,
  load_balancer: 20,
};

// Scaling architecture scores
const SCALING_SCORES = {
  serverless: 8,
  hpa_preloaded: 8,
  hpa: 5,
  keda: 5,
  vm_pool: 3,
  asg: 2,
  vertical: 0,
  manual: 0,
  none: 0,
};

function gradeFromScore(score) {
  for (const [threshold, grade, classification] of GRADE_SCALE) {
    if (score >= threshold) return { grade, classification };
  }
  return { grade: 'F', classification: 'Critical' };
}

/**
 * Calculate defense coverage score.
 *
 * @param {Array} assets - Asset inventory. Each asset may include:
 *   - cdn {boolean} CDN detected
 *   - waf {boolean} WAF detected (cloud)
 *   - rateLimiting {boolean} Rate-limit headers detected
 *   - originHidden {boolean} Origin IP hidden behind CDN
 *   - hasTunnel {boolean} Exposed via tunnel/ZTNA
 *   - vendor {string} CDN/WAF vendor name
 *   - scrubbing {string} Scrubbing vendor name
 *   - vendorClass {string} On-prem class: 'ddos_appliance'|'security_waf'|'cloud_waf'|'load_balancer'|'unknown'
 *   - onPrem {boolean} Whether this is an on-prem appliance
 *   - applianceVendor {string} On-prem appliance vendor name (for config matching)
 *   - originLeakedViaDns {boolean} MX/SPF records leak origin IP
 * @param {Object} [vendorConfigs=null] - Optional vendor config map { vendorId: { waf_credit_multiplier, vendor_class_override } }
 * @returns {Object} Defense coverage breakdown
 */
function defenseCoverageScore(assets, vendorConfigs = null) {
  const total = Math.max(assets.length, 1);

  const cdnCount = assets.filter(a => a.cdn).length;
  const cdn = Math.round((cdnCount / total) * 100);

  // Separate cloud WAF assets from on-prem WAF assets
  const cloudWafAssets = assets.filter(a => a.waf && !a.onPrem);
  const onpremWafAssets = assets.filter(a => a.onPrem && !a.waf);
  const rlCount = assets.filter(a => a.rateLimiting).length;

  // Config-aware WAF credit calculation
  let waf;
  if (cloudWafAssets.length > 0 || onpremWafAssets.length > 0) {
    let effectiveWaf = 0.0;

    // Cloud WAF assets: full credit, adjusted by config if available
    for (const a of cloudWafAssets) {
      const cdnVendor = (a.vendor || '').toLowerCase();
      let configMultiplier = null;
      if (vendorConfigs) {
        for (const [vid, vc] of Object.entries(vendorConfigs)) {
          if (cdnVendor.includes(vid) || vid.includes(cdnVendor)) {
            configMultiplier = vc.waf_credit_multiplier != null ? vc.waf_credit_multiplier : 1.0;
            break;
          }
        }
      }
      effectiveWaf += configMultiplier != null ? Math.min(1.0, 1.0 * configMultiplier) : 1.0;
    }

    // On-prem WAF assets: partial credit by vendor_class, adjusted by config
    for (const a of onpremWafAssets) {
      let vc = a.vendorClass || 'security_waf';
      const appVendor = (a.applianceVendor || '').toLowerCase();
      let configMultiplier = null;

      if (vendorConfigs && appVendor) {
        for (const [vid, vcfg] of Object.entries(vendorConfigs)) {
          if (appVendor.includes(vid) || appVendor.startsWith(vid)) {
            configMultiplier = vcfg.waf_credit_multiplier != null ? vcfg.waf_credit_multiplier : 1.0;
            // Override vendor_class if config detected specific modules
            if (vcfg.vendor_class_override) {
              vc = vcfg.vendor_class_override;
            }
            break;
          }
        }
      }

      const baseCredit = VENDOR_CLASS_WAF_CREDITS[vc] || 0.4;
      effectiveWaf += configMultiplier != null ? Math.min(1.0, baseCredit * configMultiplier) : baseCredit;
    }

    waf = Math.round((effectiveWaf / total) * 100);
  } else if (rlCount > 0) {
    // Fallback: legacy boolean waf field
    const wafCount = assets.filter(a => a.waf).length;
    if (wafCount > 0) {
      waf = Math.round((wafCount / total) * 100);
    } else {
      waf = 50;
    }
  } else {
    // Check legacy boolean waf for backward compat
    const wafCount = assets.filter(a => a.waf).length;
    waf = wafCount > 0 ? Math.round((wafCount / total) * 100) : 0;
  }

  let exposed = 0;
  let tunnelCount = 0;
  let originLeakedViaDns = false;
  for (const a of assets) {
    if (a.hasTunnel) { tunnelCount++; continue; }
    if (a.cdn && !a.originHidden) exposed++;
    else if (!a.cdn) exposed++;
    if (a.originLeakedViaDns) originLeakedViaDns = true;
  }
  let origin = Math.round((Math.max(0, cdnCount - exposed) / total) * 100);
  // MX/SPF origin leak penalty (matches backend)
  if (originLeakedViaDns) {
    origin = Math.max(0, origin - 20);
  }

  const rateLimit = Math.round((rlCount / total) * 100);

  // Protection automation
  const vendorScores = [];
  let hasScrubbing = false;
  let scrubbingQuality = 0;
  const onpremApplianceNames = [];
  let hasOnPremAppliance = false;
  for (const a of assets) {
    const vendor = (a.vendor || '').toLowerCase();
    const scrub = (a.scrubbing || '').toLowerCase();
    const appVendor = (a.applianceVendor || '').toLowerCase();
    const combined = `${vendor} ${scrub} ${appVendor}`;
    for (const [v, tier] of Object.entries(VENDOR_AUTOMATION_TIERS)) {
      if (combined.includes(v)) vendorScores.push(tier);
    }
    for (const [sv, quality] of Object.entries(SCRUBBING_QUALITY)) {
      if (scrub.includes(sv)) {
        hasScrubbing = true;
        scrubbingQuality = Math.max(scrubbingQuality, quality);
      }
    }
    if (a.onPrem) {
      hasOnPremAppliance = true;
      const name = a.applianceVendor || appVendor || 'Unknown';
      if (name && !onpremApplianceNames.includes(name)) {
        onpremApplianceNames.push(name);
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

  // Detect vendor_class flags for downstream use
  const hasOnPremDdosAppliance = assets.some(a => a.vendorClass === 'ddos_appliance' && a.onPrem);
  const hasOnPremSecurityWaf = assets.some(a => a.vendorClass === 'security_waf' && a.onPrem);
  const hasOnPremLb = assets.some(a => a.vendorClass === 'load_balancer' && a.onPrem);
  const vendorClassesDetected = [...new Set(assets.filter(a => a.vendorClass).map(a => a.vendorClass))];

  return {
    score, cdnDeployment: cdn, wafDeployment: waf,
    originProtection: origin, rateLimiting: rateLimit,
    protectionAutomation: automation, hasScrubbing, scrubbingQuality, tunnelAssets: tunnelCount,
    hasOnPremAppliance, onpremApplianceNames,
    hasOnPremDdosAppliance, hasOnPremSecurityWaf, hasOnPremLb,
    vendorClassesDetected, originLeakedViaDns,
    vendorScores, // exposed for hardeningPotential calculation
  };
}

/**
 * Calculate L7 DDoS resilience score.
 *
 * @param {Object} options
 * @param {string} [options.cdnQuality='none'] - CDN quality tier
 * @param {number} [options.cdnCoverage=0] - CDN coverage ratio (0-1)
 * @param {Object} [options.attackResults=null] - Measured attack results
 * @param {boolean} [options.hasOnlySecurityWaf=false] - True if only security_waf present (no CDN, no ddos_appliance)
 * @returns {Object}
 */
function l7ResilienceScore({ cdnQuality = 'none', cdnCoverage = 0, attackResults = null, hasOnlySecurityWaf = false } = {}) {
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
  let base = baseMap[cdnQuality] || 10;

  // Security WAFs collapse under L7 flood (DPI engine saturates CPU shared with IPS/AV).
  // If only a security_waf is present (no CDN, no DDoS appliance), cap L7 score.
  if (hasOnlySecurityWaf) {
    base = Math.min(base, 25);
  }

  return { score: Math.round(base * cov + 10 * (1 - cov)), source: 'estimated' };
}

/**
 * Calculate L7 DDoS-relevant penalty from passive recon findings (Section 4.2.5-4.2.6, v1.1/v1.5).
 * @param {Array} l7Findings - Array of {findingType: string} objects from L7 recon.
 * @param {string} [cdnVendor=null] - Detected CDN/WAF vendor name for counting-arch penalty.
 * @returns {{penalty: number, applied: Array, source: string}}
 */
function l7AttackSurfacePenalty(l7Findings, cdnVendor = null) {
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

  // Section 4.2.6 (v1.5): rate limit counting architecture gap.
  // Rate limiting IS configured but the CDN enforces it per-PoP/per-server/per-region,
  // making it bypasable via geographic IP distribution even within the stated threshold.
  if (hasRl && cdnVendor) {
    const v = cdnVendor.toLowerCase();
    for (const [key, p] of Object.entries(RL_COUNTING_ARCH_PENALTY)) {
      if (v.includes(key)) {
        penalty += p;
        applied.push({ finding: 'rate_limit_counting_arch_gap', vendor: cdnVendor, penalty: p });
        break;
      }
    }
  }

  const apiCnt = (counts.api_endpoint_discovered || 0) + (counts.graphql_endpoint || 0);
  if (apiCnt > 20) { penalty += 6; applied.push({ finding: 'large_api_surface', penalty: 6 }); }
  else if (apiCnt > 5) { penalty += 3; applied.push({ finding: 'api_surface', penalty: 3 }); }

  return { penalty, applied, source: 'l7_recon' };
}

/**
 * Calculate L3/L4 DDoS resilience score.
 *
 * @param {Object} options
 * @param {number} [options.cdnCoverage=0] - CDN coverage ratio (0-1)
 * @param {boolean} [options.hasCdn=false] - Whether CDN is present
 * @param {number} [options.exposedOrigins=0] - Number of exposed origin IPs
 * @param {string} [options.scrubbingVendor=null] - Scrubbing vendor name
 * @param {number} [options.pipelineGbps=null] - Upstream link capacity in Gbps
 * @param {string} [options.ispTier=null] - ISP DDoS protection tier ('basic'|'standard'|'premium'|'enterprise')
 * @param {string} [options.onPremVendorClass=null] - On-prem vendor class ('ddos_appliance'|'security_waf'|'load_balancer')
 * @param {boolean} [options.hasOnPremAppliance=false] - Whether on-prem appliance is present
 * @returns {Object}
 */
function l3l4ResilienceScore({
  cdnCoverage = 0, hasCdn = false, exposedOrigins = 0,
  scrubbingVendor = null, pipelineGbps = null, ispTier = null,
  onPremVendorClass = null, hasOnPremAppliance = false,
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
  const ispKnown = ispScore > 0;

  // On-prem L3/L4 bonus by vendor_class
  let onpremBonus = 0;
  if (onPremVendorClass) {
    onpremBonus = ONPREM_L3L4_BONUS[onPremVendorClass] || 0;
  }

  let base;
  if (hasScrubbing) {
    base = scrubbingQuality - (exposedOrigins > 0 ? 15 : 0);
    // ISP tier stacks with cloud scrubbing: add 20% of ISP score
    if (ispKnown) base = Math.min(100, base + Math.round(ispScore * 0.2));
    // On-prem appliance stacks with cloud scrubbing: add 10%
    if (onpremBonus > 0) base = Math.min(100, base + Math.round(onpremBonus * 0.1));
    if (pipelineBase !== null && pipelineBase < base) base = Math.round((base + pipelineBase) / 2);
  } else if (hasOnPremAppliance && onpremBonus > 0) {
    // No cloud scrubbing, but on-prem appliance provides inline protection.
    // Limited by upstream link capacity.
    base = onpremBonus - (exposedOrigins > 0 ? 10 : 0);
    // ISP stacks with on-prem at 30%
    if (ispKnown) base = Math.min(100, base + Math.round(ispScore * 0.3));
    if (pipelineBase !== null && pipelineBase < base) base = Math.round((base + pipelineBase) / 2);
  } else if (ispKnown) {
    base = ispScore - (exposedOrigins > 0 ? 10 : 0);
    if (pipelineBase !== null && pipelineBase < base) base = Math.round((base + pipelineBase) / 2);
  } else if (pipelineBase !== null) {
    base = pipelineBase - (exposedOrigins > 0 ? 15 : 0);
  } else {
    base = exposedOrigins === 0 ? 85 : 50;
  }

  base = Math.max(20, base);
  const score = hasCdn ? Math.round(base * cov + 20 * (1 - cov)) : base;
  return { score, source: 'estimated', hasScrubbing, scrubbingQuality, onpremL3l4Bonus: onpremBonus };
}

function protocolResilienceScore({ cdnQuality = 'none', cdnCoverage = 0, hasCdn = false } = {}) {
  const cov = Math.max(0, Math.min(1, cdnCoverage));
  const base = ['enterprise', 'standard'].includes(cdnQuality) ? 70 : 30;
  const score = hasCdn ? Math.round(base * cov + 50 * (1 - cov)) : 50;
  return { score, source: 'estimated' };
}

/**
 * Calculate operational resilience score.
 *
 * @param {Object} options
 * @param {string} [options.cdnQuality='none'] - CDN quality tier
 * @param {number} [options.cdnCoverage=0] - CDN coverage ratio (0-1)
 * @param {number} [options.cdnScore=0] - CDN deployment score
 * @param {boolean} [options.hasCdn=false] - Whether CDN is present
 * @param {string} [options.scalingArchitecture=null] - Scaling type: 'serverless'|'hpa_preloaded'|'hpa'|'keda'|'vm_pool'|'asg'|'vertical'|'manual'|'none'
 * @param {Array} [options.assets=null] - Assets for passive infra signal detection
 * @param {boolean} [options.hasOnPremLb=false] - On-prem load balancer detected
 * @returns {Object}
 */
function operationalResilienceScore({
  cdnQuality = 'none', cdnCoverage = 0, cdnScore = 0, hasCdn = false,
  scalingArchitecture = null, assets = null, hasOnPremLb = false,
} = {}) {
  const cov = Math.max(0, Math.min(1, cdnCoverage));
  let score;
  if (cdnScore > 80) score = Math.round(75 * cov + 30 * (1 - cov));
  else if (hasCdn) score = Math.round(50 * cov + 30 * (1 - cov));
  else score = 30;

  // Scaling architecture bonus
  let scalingBonus = 0;
  let detectedScalingArch = null;

  if (scalingArchitecture) {
    const sa = scalingArchitecture.toLowerCase();
    scalingBonus = SCALING_SCORES[sa] != null ? SCALING_SCORES[sa] : 0;
    detectedScalingArch = sa;
  }

  // Passive detection: Kubernetes headers or service mesh signals
  if (scalingBonus === 0 && assets) {
    for (const a of assets) {
      const infra = Array.isArray(a.infraSignals) ? a.infraSignals : [];
      if (infra.includes('kubernetes')) {
        scalingBonus = Math.max(scalingBonus, 5);
        detectedScalingArch = detectedScalingArch || 'hpa';
      }
      if (infra.includes('service_mesh')) {
        scalingBonus = Math.max(scalingBonus, 3);
        detectedScalingArch = detectedScalingArch || 'vm_pool';
      }
    }
  }

  // On-prem LB implies some load distribution
  if (scalingBonus === 0 && hasOnPremLb) {
    scalingBonus = 2;
    detectedScalingArch = detectedScalingArch || 'asg';
  }

  score = Math.min(100, score + scalingBonus);

  return { score, source: 'estimated', scalingBonus, scalingArchitecture: detectedScalingArch };
}

// Bot detection depth scores from empirical JS RE (2026-04-03).
// Higher = vendor JS fingerprints visitors more aggressively = harder to bypass.
const VENDOR_BOT_DETECTION_DEPTH = {
  f5: 95, 'f5 shape': 95, shape: 95,
  vercara: 90, neustar: 90,
  akamai: 85, perimeterx: 85, human: 85,
  sucuri: 80, 'ddos-guard': 80, 'ddos guard': 80,
  imperva: 78, incapsula: 78,
  kasada: 75, datadome: 70,
  radware: 65, fortinet: 60, fortiweb: 60,
  aws: 55, cloudfront: 55, checkpoint: 55, 'check point': 55,
  google: 50, gcp: 50, 'cloud armor': 50, cloudflare: 50,
  fastly: 45, 'signal sciences': 45, gcore: 45,
  lumen: 40, centurylink: 40,
  citrix: 35, netscaler: 35,
  azure: 20, microsoft: 20,
};

function evasionResistanceScore({ cdnQuality = 'none', cdnCoverage = 0, hasCdn = false, assets = null } = {}) {
  const cov = Math.max(0, Math.min(1, cdnCoverage));

  // Compute average bot detection depth from detected vendors
  const depths = [];
  for (const a of (assets || [])) {
    for (const field of ['wafProvider', 'cdnProvider', 'applianceVendor',
                          'waf_provider', 'cdn_provider', 'appliance_vendor']) {
      const v = (a[field] || '').toLowerCase();
      if (!v) continue;
      for (const [bv, bd] of Object.entries(VENDOR_BOT_DETECTION_DEPTH)) {
        if (v.includes(bv)) {
          depths.push(bd);
          break;
        }
      }
    }
  }
  const avgDepth = depths.length > 0 ? Math.round(depths.reduce((s, d) => s + d, 0) / depths.length) : 30;

  let score;
  if (hasCdn) score = Math.round(avgDepth * cov + 10 * (1 - cov));
  else score = Math.min(avgDepth, 30);
  return { score, source: 'estimated' };
}

/**
 * Calculate hardening potential metric.
 * Answers: "what % of DDactic's hardening actions can execute automatically
 * (vs. guided or manual) given the customer's detected vendor stack?"
 *
 * @param {Array<number>} vendorScores - Array of vendor automation tier scores
 * @returns {number} Hardening potential (0-100)
 */
function hardeningPotential(vendorScores) {
  if (!vendorScores || vendorScores.length === 0) return 0;
  const fullAuto = vendorScores.filter(s => s === 100).length;
  const partialAuto = vendorScores.filter(s => s > 20 && s < 100).length;
  const manualOnly = vendorScores.filter(s => s <= 20).length;
  const totalVendors = Math.max(vendorScores.length, 1);
  return Math.round((fullAuto * 100 + partialAuto * 60 + manualOnly * 20) / totalVendors);
}

/**
 * Calculate complete OPI score.
 *
 * @param {Object} options
 * @param {Array} options.assets - Asset inventory. Each asset may include:
 *   - fqdn {string} Fully qualified domain name
 *   - cdn {boolean} CDN detected
 *   - waf {boolean} WAF detected (cloud)
 *   - rateLimiting {boolean} Rate-limit headers detected
 *   - originHidden {boolean} Origin IP hidden behind CDN
 *   - hasTunnel {boolean} Exposed via tunnel/ZTNA
 *   - vendor {string} CDN/WAF vendor name
 *   - scrubbing {string} Scrubbing vendor name
 *   - vendorClass {string} 'ddos_appliance'|'security_waf'|'cloud_waf'|'load_balancer'|'unknown'
 *   - onPrem {boolean} Whether this is an on-prem appliance
 *   - applianceVendor {string} On-prem appliance vendor name
 *   - originLeakedViaDns {boolean} MX/SPF origin IP leak
 *   - infraSignals {Array<string>} Infrastructure signals (e.g. 'kubernetes', 'service_mesh')
 * @param {string} [options.cdnQuality='none'] - CDN quality tier
 * @param {string} [options.scrubbingVendor] - Scrubbing vendor name
 * @param {number} [options.pipelineGbps] - Upstream link capacity
 * @param {string} [options.ispTier] - ISP DDoS protection tier
 * @param {Array} [options.l7Findings=null] - L7 recon findings for attack surface penalty
 * @param {Object} [options.vendorConfigs=null] - Vendor config map for config-aware WAF scoring
 * @param {Array<string>} [options.excludedSlds=null] - SLDs to exclude from scoring (AI-flagged third-party)
 * @param {string} [options.scalingArchitecture=null] - Scaling architecture type
 * @returns {Object} OPI result with score, grade, component breakdown, and hardening potential
 */
function calculateOPI({
  assets, cdnQuality = 'none',
  scrubbingVendor = null, pipelineGbps = null, ispTier = null,
  l7Findings = null, vendorConfigs = null, excludedSlds = null,
  scalingArchitecture = null,
} = {}) {
  // AI SLD exclusion: filter out assets belonging to excluded SLDs
  let filteredAssets = assets;
  if (excludedSlds && excludedSlds.length > 0) {
    filteredAssets = assets.filter(a => {
      const fqdn = a.fqdn || '';
      return !excludedSlds.some(sld => fqdn.endsWith('.' + sld) || fqdn === sld);
    });
  }

  const total = Math.max(filteredAssets.length, 1);
  const cdnCount = filteredAssets.filter(a => a.cdn).length;
  const cdnCov = cdnCount / total;
  const hasCdn = cdnQuality !== 'none' || cdnCount > 0;
  const exposed = filteredAssets.filter(a => a.cdn && !a.originHidden).length
    + filteredAssets.filter(a => !a.cdn && !a.hasTunnel).length;

  const dc = defenseCoverageScore(filteredAssets, vendorConfigs);

  // Pre-compute vendor_class flags for L7 and L3/L4
  const hasOnPremDdosAppliance = filteredAssets.some(a => a.vendorClass === 'ddos_appliance' && a.onPrem);
  const hasOnPremSecurityWaf = filteredAssets.some(a => a.vendorClass === 'security_waf' && a.onPrem);
  const hasOnPremLb = filteredAssets.some(a => a.vendorClass === 'load_balancer' && a.onPrem);
  const hasOnlySecurityWaf = hasOnPremSecurityWaf && !hasOnPremDdosAppliance && !hasCdn;

  // Determine on-prem vendor class for L3/L4 (pick highest priority)
  let onPremVendorClass = null;
  if (hasOnPremDdosAppliance) onPremVendorClass = 'ddos_appliance';
  else if (hasOnPremSecurityWaf) onPremVendorClass = 'security_waf';
  else if (hasOnPremLb) onPremVendorClass = 'load_balancer';

  const l7 = l7ResilienceScore({ cdnQuality, cdnCoverage: cdnCov, hasOnlySecurityWaf });

  // Detect dominant CDN vendor from asset list for counting-arch penalty (Section 4.2.6)
  const vendorStrings = filteredAssets.map(a => (a.vendor || '').toLowerCase()).filter(Boolean);
  const dominantVendor = vendorStrings.length > 0 ? vendorStrings[0] : null;

  // L7 Attack Surface penalties (Section 4.2.5-4.2.6, v1.1/v1.5)
  const l7Surface = l7AttackSurfacePenalty(l7Findings, dominantVendor);
  if (l7Surface.penalty > 0 && l7.source === 'estimated') {
    l7.score = Math.max(0, l7.score - l7Surface.penalty);
    l7.l7SurfacePenalty = l7Surface;
  }

  const l3l4 = l3l4ResilienceScore({
    cdnCoverage: cdnCov, hasCdn, exposedOrigins: exposed,
    scrubbingVendor, pipelineGbps, ispTier,
    onPremVendorClass, hasOnPremAppliance: dc.hasOnPremAppliance,
  });
  const proto = protocolResilienceScore({ cdnQuality, cdnCoverage: cdnCov, hasCdn });
  const ops = operationalResilienceScore({
    cdnQuality, cdnCoverage: cdnCov, cdnScore: dc.cdnDeployment, hasCdn,
    scalingArchitecture, assets: filteredAssets, hasOnPremLb,
  });
  const evasion = evasionResistanceScore({ cdnQuality, cdnCoverage: cdnCov, hasCdn, assets });

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

  // Hardening potential from detected vendor scores
  const hp = hardeningPotential(dc.vendorScores);

  return {
    score, grade, classification,
    tier: hasL7Recon ? 'estimated' : tier,
    components: {
      defenseCoverage: dc, l7Attack: l7, l3l4Attack: l3l4,
      protocol: proto, operational: ops, evasion,
    },
    weights: WEIGHTS,
    assetCount: filteredAssets.length,
    excludedAssetCount: assets.length - filteredAssets.length,
    hardeningPotential: hp,
    version: '1.5.0',
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
    evasionResistanceScore, gradeFromScore, normalizedOPI, hardeningPotential,
    WEIGHTS, GRADE_SCALE, VENDOR_AUTOMATION_TIERS, SCRUBBING_QUALITY,
    VENDOR_CLASS_WAF_CREDITS, ONPREM_L3L4_BONUS, SCALING_SCORES,
  };
}

// ESM / browser export
if (typeof globalThis !== 'undefined') {
  globalThis.OPICalculator = {
    calculateOPI, defenseCoverageScore, gradeFromScore, normalizedOPI, hardeningPotential,
    WEIGHTS, GRADE_SCALE,
  };
}
