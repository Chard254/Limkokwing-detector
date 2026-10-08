import { config } from './config.js';

const suspiciousKeywords = [
  'login', 'verify', 'secure', 'update', 'example', 'account', 'free', 'bonus',
  'password', 'wallet', 'win', 'gift', 'claim', 'limited', 'urgent', 'confirm', 'signin', 'reset',
];

export function extractUrl(text) {
  const match = String(text || '').match(/(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/i);
  if (!match) return null;
  const value = match[0].replace(/[.,;:!?\])}]+$/g, '');
  return value.toLowerCase().startsWith('www.') ? `https://${value}` : value;
}

function getFeatures(input) {
  const url = new URL(input);
  const domain = url.host.toLowerCase();
  const value = input.trim().toLowerCase();
  return {
    url_length: value.length,
    domain_length: domain.length,
    has_http: value.startsWith('https://') ? 1 : 0,
    has_at_symbol: value.includes('@') ? 1 : 0,
    has_hyphen: domain.includes('-') ? 1 : 0,
    dot_count: domain.split('.').length - 1,
    digit_count: [...domain].filter((char) => /\d/.test(char)).length,
    keyword_count: suspiciousKeywords.filter((word) => value.includes(word)).length,
    has_ip_address: /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$/.test(domain) ? 1 : 0,
  };
}

async function checkVirusTotal(url) {
  if (!config.virusTotalApiKey) return { available: false, source: 'VirusTotal', error: 'VirusTotal API key missing' };
  const id = Buffer.from(url).toString('base64url').replace(/=+$/g, '');
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': config.virusTotalApiKey }, signal: AbortSignal.timeout(20000),
    });
    if (response.ok) {
      const data = await response.json();
      const stats = data?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      return { available: true, source: 'VirusTotal', verdict: malicious ? 'Phishing' : suspicious ? 'Suspicious' : 'Safe', malicious, suspicious, harmless: stats.harmless || 0, undetected: stats.undetected || 0, stats };
    }
    const lookupError = `VirusTotal lookup returned HTTP ${response.status}`;
    const payload = new URLSearchParams({ url });
    const submitted = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST', headers: { 'x-apikey': config.virusTotalApiKey, 'content-type': 'application/x-www-form-urlencoded' },
      body: payload, signal: AbortSignal.timeout(20000),
    });
    const body = await submitted.json().catch(() => ({}));
    return { available: false, source: 'VirusTotal', message: 'URL lookup failed. Submission attempted.', lookup_error: lookupError,
      submission: submitted.ok ? { available: true, source: 'VirusTotal', analysis_id: body?.data?.id, raw: body } : { available: false, source: 'VirusTotal', error: `HTTP ${submitted.status}` } };
  } catch (error) {
    return { available: false, source: 'VirusTotal', error: error.message };
  }
}

export async function analyzeUrl(input) {
  const url = input.trim();
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('A valid URL is required'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error('Only HTTP and HTTPS URLs can be scanned');

  const features = getFeatures(url);
  const reasons = [];
  let score = 0;
  if (features.url_length > 50) { score += 1; reasons.push('URL is very long'); }
  for (const word of suspiciousKeywords) {
    if (url.toLowerCase().includes(word)) { score += 1; reasons.push(`Contains suspicious keyword: ${word}`); }
  }
  if (features.has_at_symbol) { score += 2; reasons.push('URL contains @ symbol'); }
  if (!features.has_http) { score += 1; reasons.push('URL does not use HTTPS'); }
  if (features.has_hyphen) { score += 1; reasons.push('Domain contains hyphen'); }
  if (features.dot_count >= 3) { score += 1; reasons.push('URL has many subdomains'); }
  if (features.digit_count > 0) { score += 1; reasons.push('Domain contains numbers'); }
  if (features.has_ip_address) { score += 2; reasons.push('URL uses an IP address instead of a normal domain'); }

  let verdict = score >= 4 ? 'Phishing' : score >= 2 ? 'Suspicious' : 'Safe';
  let riskLevel = score >= 4 ? 'High' : score >= 2 ? 'Medium' : 'Low';
  let advice = verdict === 'Phishing' ? 'Do not open this link. It may be trying to steal your information.'
    : verdict === 'Suspicious' ? 'Be careful. Verify the source before opening this link.'
      : 'This link looks safe based on the current checks.';
  const threatIntel = await checkVirusTotal(url);
  if (threatIntel.available) {
    reasons.push(`VirusTotal verdict: ${threatIntel.verdict}`);
    reasons.push(`VirusTotal stats - malicious: ${threatIntel.malicious}, suspicious: ${threatIntel.suspicious}`);
    if (threatIntel.verdict === 'Phishing') { verdict = 'Phishing'; riskLevel = 'High'; advice = 'Do not open this link. VirusTotal has flagged it as dangerous.'; }
    else if (threatIntel.verdict === 'Suspicious' && verdict === 'Safe') { verdict = 'Suspicious'; riskLevel = 'Medium'; advice = 'Be careful. VirusTotal found suspicious signals.'; }
  } else {
    reasons.push(`VirusTotal unavailable: ${threatIntel.error || threatIntel.message || 'lookup failed'}`);
  }
  reasons.push('Node API uses rule-based detection; the Python scikit-learn model is not loaded in Node.');
  return { url, score, risk_score: score, risk_level: riskLevel, result: verdict, verdict, is_phishing: verdict !== 'Safe', reasons, features, ml_prediction: 'Not available in Node API', ml_confidence: null, advice, threat_intelligence: threatIntel };
}

export function normalizeScanResult(url, raw) {
  const reasons = raw.reasons || raw.reason || [];
  return { url: raw.url || url, verdict: raw.verdict || raw.result || 'Unknown', risk_score: raw.risk_score ?? raw.score ?? 0,
    risk_level: raw.risk_level || 'Unknown', reasons: Array.isArray(reasons) ? reasons : [reasons], advice: raw.advice || 'Be careful before opening this link.' };
}
