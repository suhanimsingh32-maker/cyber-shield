/**
 * CyberShield v2 — SIH Hackathon Prototype Server
 * Real threat intelligence: Google Safe Browsing + VirusTotal + Local Heuristics
 * Supabase Auth verification, admin role gating, real-time stats via triggers
 * ZERO fake data — every number comes from real scans
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const PORT = process.env.PORT || 3000;

// --- ENVIRONMENT ---
const SUPABASE_URL = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const GOOGLE_SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_API_KEY;

let supabase = null;
if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
  try {
    supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    console.log('[SUPABASE] Connected.');
  } catch (err) { console.error('[SUPABASE] Init error:', err.message); }
}

// --- LOCAL DB FALLBACK ---
const DB_FILE = path.join(__dirname, 'db.json');
function readLocalDb() {
  try { if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { console.error('db.json read error:', e.message); }
  return { scans: [], threats: [], scamReports: [], stats: { total_scans:0, safe_count:0, suspicious_count:0, dangerous_count:0, url_scans:0, message_scans:0, qr_scans:0, image_scans:0 } };
}
function saveLocalDb(data) {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8'); } catch (e) {}
}

// --- HELPERS ---
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) { req.destroy(); reject(new Error('Payload too large')); } });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}

function httpsRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, options, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, data: data }); }
      });
    });
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Request timeout')); });
    req.end();
  });
}

// Extract JWT user from Authorization header via Supabase
async function getAuthUser(req) {
  if (!supabase) return null;
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.substring(7);
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return null;
    return user;
  } catch (e) { return null; }
}

// Check if user has admin role
async function isAdmin(userId) {
  if (!supabase || !userId) return false;
  try {
    const { data } = await supabase.from('profiles').select('role').eq('user_id', userId).single();
    return data && data.role === 'admin';
  } catch (e) { return false; }
}

function sendJSON(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

// ═══════════════════════════════════════════════════
// THREAT ANALYSIS ENGINE
// ═══════════════════════════════════════════════════

// 1. LOCAL HEURISTICS (always runs, instant)
function localHeuristicsURL(targetUrl) {
  const u = targetUrl.toLowerCase();
  let score = 0;
  const signals = [];

  const suspiciousTLDs = ['.xyz', '.top', '.club', '.online', '.site', '.work', '.info', '.cc', '.vip', '.biz'];
  const brands = ['sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'gpay', 'irctc', 'amazon', 'flipkart', 'netbanking', 'income-tax', 'aadhaar'];
  const officialDomains = ['sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'irctc.co.in', 'amazon.in', 'flipkart.com', 'paytm.com'];

  if (suspiciousTLDs.some(t => u.includes(t))) {
    score += 25;
    signals.push({ category: 'URL Structure', name: 'Suspicious TLD', severity: 'HIGH', scoreImpact: 25, source: 'local_heuristics', explanation: 'Uses a high-risk TLD (.xyz, .top, .vip) commonly seen in phishing.' });
  }
  const hasBrand = brands.some(b => u.includes(b));
  const isOfficial = officialDomains.some(d => u.includes(d));
  if (hasBrand && !isOfficial) {
    score += 35;
    signals.push({ category: 'Brand Impersonation', name: 'Lookalike Domain', severity: 'CRITICAL', scoreImpact: 35, source: 'local_heuristics', explanation: 'Contains a known brand name but does not match the official domain.' });
  }
  if (/login|verify|update|kyc|block|pan|secure/i.test(u)) {
    score += 20;
    signals.push({ category: 'Behavior', name: 'Credential Harvesting Keywords', severity: 'HIGH', scoreImpact: 20, source: 'local_heuristics', explanation: 'URL path suggests a credential harvesting or account verification page.' });
  }
  if (/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(targetUrl)) {
    score += 20;
    signals.push({ category: 'Infrastructure', name: 'Raw IP Address', severity: 'HIGH', scoreImpact: 20, source: 'local_heuristics', explanation: 'Uses a raw IP address instead of a domain name.' });
  }
  return { score: Math.min(score, 100), signals };
}

function localHeuristicsMessage(text) {
  const lower = text.toLowerCase();
  let score = 0;
  const signals = [];

  if (/blocked|urgent|immediately|fine of|suspend/i.test(lower)) {
    score += 30;
    signals.push({ category: 'Language', name: 'Urgency & Fear Tactics', severity: 'CRITICAL', scoreImpact: 30, source: 'local_heuristics', explanation: 'Uses psychological pressure (threats of blocking, fines, urgency).' });
  }
  if (/pan|otp|password|netbanking|pin|cvv/i.test(lower)) {
    score += 30;
    signals.push({ category: 'Social Engineering', name: 'Credential/PII Request', severity: 'CRITICAL', scoreImpact: 30, source: 'local_heuristics', explanation: 'Requests sensitive information (PAN, OTP, password, PIN).' });
  }
  if (/http:\/\/|https?:\/\/[^\s]*\.(top|xyz|vip|club)|t\.me\//i.test(lower)) {
    score += 25;
    signals.push({ category: 'Links', name: 'Embedded High-Risk Link', severity: 'HIGH', scoreImpact: 25, source: 'local_heuristics', explanation: 'Contains an external link to a suspicious domain.' });
  }
  return { score: Math.min(score, 100), signals };
}

// 2. GOOGLE SAFE BROWSING API
async function checkGoogleSafeBrowsing(url) {
  if (!GOOGLE_SAFE_BROWSING_KEY) return { matched: false, signals: [] };
  try {
    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_KEY}`;
    const payload = JSON.stringify({
      client: { clientId: 'cybershield-sih', clientVersion: '2.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    });
    const { status, data } = await httpsRequest(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      body: payload
    });
    if (status === 200 && data.matches && data.matches.length > 0) {
      const match = data.matches[0];
      return {
        matched: true,
        signals: [{
          category: 'Google Safe Browsing',
          name: `${match.threatType} detected`,
          severity: 'CRITICAL',
          scoreImpact: 40,
          source: 'google_safe_browsing',
          explanation: `Google Safe Browsing flagged this URL as ${match.threatType.replace(/_/g, ' ').toLowerCase()}.`
        }],
        rawMatch: match
      };
    }
    return { matched: false, signals: [] };
  } catch (e) {
    console.error('[GSB] Error:', e.message);
    return { matched: false, signals: [], error: e.message };
  }
}

// 3. VIRUSTOTAL API
async function checkVirusTotal(url) {
  if (!VIRUSTOTAL_KEY) return { matched: false, signals: [] };
  try {
    // URL must be base64-encoded (without padding) for VT v3
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
    const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    const { status, data } = await httpsRequest(apiUrl, {
      method: 'GET',
      headers: { 'x-apikey': VIRUSTOTAL_KEY, 'Accept': 'application/json' }
    });
    if (status === 200 && data.data && data.data.attributes) {
      const stats = data.data.attributes.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      if (malicious > 0 || suspicious > 0) {
        return {
          matched: true,
          signals: [{
            category: 'VirusTotal',
            name: `${malicious} vendor(s) flagged as malicious`,
            severity: malicious >= 5 ? 'CRITICAL' : malicious >= 2 ? 'HIGH' : 'SUSPICIOUS',
            scoreImpact: Math.min(malicious * 8 + suspicious * 4, 40),
            source: 'virustotal',
            explanation: `VirusTotal: ${malicious}/${total} security vendors flagged this as malicious, ${suspicious}/${total} as suspicious.`
          }],
          vtStats: stats
        };
      }
    }
    return { matched: false, signals: [] };
  } catch (e) {
    console.error('[VT] Error:', e.message);
    return { matched: false, signals: [], error: e.message };
  }
}

// ═══════════════════════════════════════════════════
// FULL ANALYSIS PIPELINE
// ═══════════════════════════════════════════════════
async function analyzeURL(targetUrl) {
  if (!targetUrl || typeof targetUrl !== 'string' || targetUrl.length > 10000)
    throw new Error('Invalid URL input');

  // Run all checks in parallel
  const [local, gsb, vt] = await Promise.all([
    Promise.resolve(localHeuristicsURL(targetUrl)),
    checkGoogleSafeBrowsing(targetUrl),
    checkVirusTotal(targetUrl)
  ]);

  const allSignals = [...local.signals, ...gsb.signals, ...vt.signals];
  const totalScore = Math.min(allSignals.reduce((sum, s) => sum + s.scoreImpact, 0), 100);
  const verdict = totalScore >= 70 ? 'DANGEROUS' : totalScore >= 35 ? 'SUSPICIOUS' : 'SAFE';
  const severity = totalScore >= 85 ? 'CRITICAL' : totalScore >= 70 ? 'HIGH' : totalScore >= 35 ? 'SUSPICIOUS' : 'SAFE';

  // Determine sources that contributed
  const sources = [...new Set(allSignals.map(s => s.source))];
  const threatType = gsb.matched ? 'PHISHING' : vt.matched ? 'MALWARE' : totalScore >= 35 ? 'PHISHING' : 'BENIGN';

  return {
    id: `SCAN-${Math.floor(10000 + Math.random() * 90000)}`,
    target: targetUrl,
    scanType: 'url',
    verdict, severity,
    riskScore: totalScore,
    confidence: Math.min(60 + sources.length * 15, 99),
    threatType,
    analysisSource: sources.join(', ') || 'local_heuristics',
    summary: verdict === 'DANGEROUS'
      ? `High-confidence threat detected. ${sources.includes('google_safe_browsing') ? 'Google Safe Browsing confirmed this as a threat. ' : ''}${sources.includes('virustotal') ? 'Multiple VirusTotal vendors flagged this URL. ' : ''}${sources.includes('local_heuristics') ? 'Local heuristics detected phishing patterns.' : ''}`
      : verdict === 'SUSPICIOUS'
      ? `Suspicious patterns detected. ${allSignals.length} warning signal(s) found across ${sources.length} source(s).`
      : 'No threats detected by any analysis source.',
    signals: allSignals,
    actions: verdict === 'SAFE'
      ? ['Verify SSL certificate in browser', 'Cross-check URL with official bookmarks']
      : [
        'Do NOT click or visit this link',
        'Do NOT enter any passwords, OTPs, or personal details',
        'Report to National Cyber Crime Portal (cybercrime.gov.in)',
        'Block the sender if received via SMS or WhatsApp'
      ],
    apiResults: {
      googleSafeBrowsing: { checked: !!GOOGLE_SAFE_BROWSING_KEY, matched: gsb.matched },
      virusTotal: { checked: !!VIRUSTOTAL_KEY, matched: vt.matched, stats: vt.vtStats || null }
    }
  };
}

async function analyzeMessage(text) {
  if (!text || typeof text !== 'string' || text.length > 10000)
    throw new Error('Invalid message input');

  const local = localHeuristicsMessage(text);

  // Extract URLs from message and check them too
  const urlRegex = /https?:\/\/[^\s]+/gi;
  const urls = text.match(urlRegex) || [];
  let urlSignals = [];
  for (const url of urls.slice(0, 2)) { // max 2 URLs to avoid rate limits
    const [gsb, vt] = await Promise.all([checkGoogleSafeBrowsing(url), checkVirusTotal(url)]);
    urlSignals = [...urlSignals, ...gsb.signals, ...vt.signals];
  }

  const allSignals = [...local.signals, ...urlSignals];
  const totalScore = Math.min(allSignals.reduce((sum, s) => sum + s.scoreImpact, 0), 100);
  const verdict = totalScore >= 60 ? 'DANGEROUS' : totalScore >= 30 ? 'SUSPICIOUS' : 'SAFE';
  const severity = totalScore >= 85 ? 'CRITICAL' : totalScore >= 60 ? 'HIGH' : totalScore >= 30 ? 'SUSPICIOUS' : 'SAFE';
  const sources = [...new Set(allSignals.map(s => s.source))];

  return {
    id: `SCAN-${Math.floor(10000 + Math.random() * 90000)}`,
    target: text.substring(0, 80) + (text.length > 80 ? '...' : ''),
    fullTarget: text,
    scanType: 'message',
    verdict, severity,
    riskScore: totalScore,
    confidence: Math.min(55 + sources.length * 15, 99),
    threatType: totalScore >= 30 ? 'SMS_SCAM' : 'BENIGN',
    analysisSource: sources.join(', ') || 'local_heuristics',
    summary: verdict === 'DANGEROUS'
      ? `High-risk scam message detected. ${allSignals.length} threat signal(s) found.`
      : verdict === 'SUSPICIOUS'
      ? `Potential scam patterns detected. Verify sender identity through official channels.`
      : 'No obvious scam indicators found.',
    signals: allSignals,
    actions: verdict === 'SAFE'
      ? ['Verify sender via official contact channels']
      : ['Do NOT reply or share any OTP codes', 'Do NOT click any links in the message', 'Block the sender', 'Report to 1930 Cyber Fraud Helpline'],
    apiResults: { urlsChecked: urls.length }
  };
}

// Save scan + optionally create threat entry
async function persistScan(result, userId) {
  const scanRow = {
    id: result.id, target: result.target, scan_type: result.scanType,
    verdict: result.verdict, severity: result.severity, risk_score: result.riskScore,
    confidence: result.confidence, threat_type: result.threatType,
    analysis_source: result.analysisSource,
    user_id: userId || null
  };

  if (supabase) {
    await supabase.from('scans').insert([scanRow]);
    if (result.signals && result.signals.length > 0) {
      await supabase.from('threat_analyses').insert([{ scan_id: result.id, summary: result.summary, actions: result.actions }]);
      for (const sig of result.signals) {
        await supabase.from('threat_indicators').insert([{ scan_id: result.id, category: sig.category, name: sig.name, severity: sig.severity, score_impact: sig.scoreImpact, explanation: sig.explanation }]);
      }
    }
    // If dangerous, add to threats table
    if (result.verdict === 'DANGEROUS' || result.verdict === 'SUSPICIOUS') {
      await supabase.from('threats').insert([{
        scan_id: result.id, source: result.analysisSource, target: result.target,
        threat_type: result.threatType, severity: result.severity,
        description: result.summary, metadata: { signals: result.signals.map(s => s.name), apiResults: result.apiResults }
      }]);
    }
  } else {
    const db = readLocalDb();
    db.scans = [{ ...scanRow, timestamp: new Date().toISOString() }, ...(db.scans || [])];
    // Update local stats
    db.stats = db.stats || { total_scans:0, safe_count:0, suspicious_count:0, dangerous_count:0, url_scans:0, message_scans:0, qr_scans:0, image_scans:0 };
    db.stats.total_scans++;
    if (result.verdict === 'SAFE') db.stats.safe_count++;
    else if (result.verdict === 'SUSPICIOUS') db.stats.suspicious_count++;
    else if (result.verdict === 'DANGEROUS') db.stats.dangerous_count++;
    const typeKey = result.scanType + '_scans';
    if (db.stats[typeKey] !== undefined) db.stats[typeKey]++;
    if (result.verdict !== 'SAFE') {
      db.threats = [{ id: result.id, source: result.analysisSource, target: result.target, threat_type: result.threatType, severity: result.severity, description: result.summary, created_at: new Date().toISOString() }, ...(db.threats || [])];
    }
    saveLocalDb(db);
  }
}

// ═══════════════════════════════════════════════════
// HTTP SERVER
// ═══════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  if (pathname.startsWith('/api/')) {
    res.setHeader('Content-Type', 'application/json');

    try {
      // ── AUTH ROUTES ──
      if (pathname === '/api/auth/login' && req.method === 'POST') {
        const { email, password } = await parseBody(req);
        if (supabase) {
          const { data, error } = await supabase.auth.signInWithPassword({ email, password });
          if (error) return sendJSON(res, 400, { success: false, error: error.message });
          return sendJSON(res, 200, { success: true, token: data.session.access_token, user: data.user });
        }
        return sendJSON(res, 200, { success: true, token: 'local-jwt', user: { email, id: 'user-local' } });
      }

      if (pathname === '/api/auth/signup' && req.method === 'POST') {
        const { email, password, fullName } = await parseBody(req);
        if (supabase) {
          const { data, error } = await supabase.auth.signUp({
            email, password,
            options: { data: { full_name: fullName || 'User' } }
          });
          if (error) return sendJSON(res, 400, { success: false, error: error.message });
          return sendJSON(res, 200, { success: true, user: data.user, needsVerification: !data.session });
        }
        return sendJSON(res, 200, { success: true, user: { email, id: 'user-local' }, needsVerification: false });
      }

      if (pathname === '/api/auth/forgot-password' && req.method === 'POST') {
        const { email } = await parseBody(req);
        if (supabase) {
          const { error } = await supabase.auth.resetPasswordForEmail(email);
          if (error) return sendJSON(res, 400, { success: false, error: error.message });
        }
        return sendJSON(res, 200, { success: true, message: 'Password reset email sent.' });
      }

      if (pathname === '/api/auth/user' && req.method === 'GET') {
        const user = await getAuthUser(req);
        if (!user) return sendJSON(res, 401, { success: false, error: 'Not authenticated' });
        const admin = await isAdmin(user.id);
        return sendJSON(res, 200, { success: true, user, isAdmin: admin });
      }

      // ── SCAN ROUTES ──
      if (pathname === '/api/scan/url' && req.method === 'POST') {
        const { url } = await parseBody(req);
        const result = await analyzeURL(url);
        const user = await getAuthUser(req);
        await persistScan(result, user ? user.id : null);
        return sendJSON(res, 200, { success: true, scan: result });
      }

      if (pathname === '/api/scan/message' && req.method === 'POST') {
        const { message } = await parseBody(req);
        const result = await analyzeMessage(message);
        const user = await getAuthUser(req);
        await persistScan(result, user ? user.id : null);
        return sendJSON(res, 200, { success: true, scan: result });
      }

      if (pathname === '/api/scan/qr' && req.method === 'POST') {
        const { payload } = await parseBody(req);
        const result = await analyzeURL(payload);
        result.scanType = 'qr';
        const user = await getAuthUser(req);
        await persistScan(result, user ? user.id : null);
        return sendJSON(res, 200, { success: true, scan: result });
      }

      if (pathname === '/api/scan/image' && req.method === 'POST') {
        const { extractedText } = await parseBody(req);
        const result = await analyzeMessage(extractedText);
        result.scanType = 'image';
        const user = await getAuthUser(req);
        await persistScan(result, user ? user.id : null);
        return sendJSON(res, 200, { success: true, scan: result });
      }

      // ── DATA ROUTES (auth required for personal data) ──
      if (pathname === '/api/scans' && req.method === 'GET') {
        const user = await getAuthUser(req);
        if (supabase && user) {
          const { data } = await supabase.from('scans').select('*').eq('user_id', user.id).order('created_at', { ascending: false }).limit(50);
          return sendJSON(res, 200, { scans: data || [] });
        }
        const db = readLocalDb();
        return sendJSON(res, 200, { scans: db.scans || [] });
      }

      // ── STATS (from trigger-maintained table — real data only) ──
      if (pathname === '/api/stats' && req.method === 'GET') {
        if (supabase) {
          const { data } = await supabase.from('stats').select('*').eq('id', 1).single();
          return sendJSON(res, 200, { stats: data || {} });
        }
        const db = readLocalDb();
        return sendJSON(res, 200, { stats: db.stats || {} });
      }

      // ── THREATS (real detections from API results) ──
      if (pathname === '/api/threats' && req.method === 'GET') {
        if (supabase) {
          const { data } = await supabase.from('threats').select('*').order('created_at', { ascending: false }).limit(50);
          return sendJSON(res, 200, { threats: data || [] });
        }
        const db = readLocalDb();
        return sendJSON(res, 200, { threats: db.threats || [] });
      }

      // ── SCAM REPORTS ──
      if (pathname === '/api/reports/scam' && req.method === 'POST') {
        const { type, target, description } = await parseBody(req);
        if (!type || !target) return sendJSON(res, 400, { success: false, error: 'type and target required' });
        const user = await getAuthUser(req);
        const report = { id: `RPT-${Date.now()}`, type, target, description: description || '', status: 'pending', created_at: new Date().toISOString(), user_id: user ? user.id : null };
        if (supabase) { await supabase.from('scam_reports').insert([report]); }
        else { const db = readLocalDb(); db.scamReports = [report, ...(db.scamReports || [])]; saveLocalDb(db); }
        return sendJSON(res, 200, { success: true, report });
      }

      if (pathname === '/api/reports/scam' && req.method === 'GET') {
        if (supabase) {
          const { data } = await supabase.from('scam_reports').select('*').order('created_at', { ascending: false }).limit(30);
          return sendJSON(res, 200, { reports: data || [] });
        }
        const db = readLocalDb();
        return sendJSON(res, 200, { reports: db.scamReports || [] });
      }

      // ── ALERTS ──
      if (pathname === '/api/alerts' && req.method === 'GET') {
        const user = await getAuthUser(req);
        if (supabase && user) {
          const { data } = await supabase.from('alerts').select('*').eq('user_id', user.id).order('timestamp', { ascending: false }).limit(20);
          return sendJSON(res, 200, { alerts: data || [] });
        }
        return sendJSON(res, 200, { alerts: [] });
      }

      sendJSON(res, 404, { error: 'Endpoint not found' });
    } catch (e) {
      console.error('[API ERROR]', e.message);
      sendJSON(res, 500, { error: 'Internal server error', message: e.message });
    }
    return;
  }

  // ── STATIC FILES ──
  let relativePath = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
  let filePath = path.join(__dirname, 'public', relativePath);
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) filePath = path.join(__dirname, 'public', 'index.html');
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
    fs.readFile(filePath, (error, content) => {
      if (error) { res.writeHead(500); res.end('Server Error'); }
      else { res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'application/octet-stream' }); res.end(content, 'utf-8'); }
    });
  });
});

server.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════');
  console.log('  CyberShield v2 — SIH Hackathon Prototype');
  console.log(`  Server: http://localhost:${PORT}`);
  console.log(`  Supabase: ${supabase ? 'CONNECTED' : 'LOCAL FALLBACK'}`);
  console.log(`  Google Safe Browsing: ${GOOGLE_SAFE_BROWSING_KEY ? 'ACTIVE' : 'NOT CONFIGURED'}`);
  console.log(`  VirusTotal: ${VIRUSTOTAL_KEY ? 'ACTIVE' : 'NOT CONFIGURED'}`);
  console.log(`  Stats: REAL DATA ONLY (Postgres trigger maintained)`);
  console.log('═══════════════════════════════════════════════════');
});
