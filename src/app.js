import express from 'express';
import { timingSafeEqual } from 'node:crypto';
import { db } from './database.js';
import { config } from './config.js';
import { analyzeUrl, normalizeScanResult } from './detector.js';
import { markWhatsAppMessageAsRead, recordWhatsAppStatus, sendWhatsAppMessage } from './integrations.js';
import { processMessage } from './conversation.js';
import { verifyMetaWebhookSignature } from './meta_webhooks.js';

export const app = express();
app.use(express.json({ limit: '1mb', verify: (req, _res, buffer) => { req.rawBody = Buffer.from(buffer); } }));
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, X-N8N-Secret');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/', (_req, res) => res.json({ success: true, message: 'Phishing Detection Platform API is running.' }));
app.get('/health', (_req, res) => res.json({ success: true, status: 'healthy' }));

app.post('/scan-url', async (req, res) => {
  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
  if (!url) return res.status(422).json({ detail: [{ loc: ['body', 'url'], msg: 'A URL is required', type: 'value_error' }] });
  try {
    const parsed = new URL(url);
    if (!['https:', 'http:'].includes(parsed.protocol) || !parsed.hostname) throw new Error('Invalid URL');
    const existing = db.prepare('SELECT * FROM url_scans WHERE url = ? ORDER BY created_at DESC, id DESC LIMIT 1').get(url);
    const forceRescan = ['true', '1'].includes(String(req.query.rescan)) || String(req.query.force) === 'true';
    if (existing && !forceRescan) {
      const result = {
        scan_id: existing.id, url: existing.url, verdict: existing.verdict,
        risk_score: existing.risk_score ?? existing.score ?? 0, risk_level: existing.risk_level || 'Unknown',
        reasons: (existing.reason || '').split(', ').filter(Boolean), advice: existing.advice || 'Be careful before opening this link.',
        last_scanned_at: new Date(`${existing.created_at.replace(' ', 'T')}Z`).toISOString(),
      };
      return res.json({ success: true, cached: true, data: result });
    }
    const result = normalizeScanResult(url, await analyzeUrl(url));
    const reasonText = result.reasons.join(', ');
    const saved = db.prepare(`INSERT INTO url_scans (url,result,verdict,risk_level,score,risk_score,reasons,reason,advice,source)
      VALUES (?,?,?,?,?,?,?,?,?,?)`).run(url, result.verdict, result.verdict, result.risk_level, result.risk_score,
      result.risk_score, reasonText, reasonText, result.advice, 'web');
    const row = db.prepare('SELECT created_at FROM url_scans WHERE id = ?').get(saved.lastInsertRowid);
    return res.json({ success: true, cached: false, data: { scan_id: Number(saved.lastInsertRowid), ...result,
      last_scanned_at: new Date(`${row.created_at.replace(' ', 'T')}Z`).toISOString() } });
  } catch (error) {
    if (error instanceof TypeError || error.message === 'Invalid URL' || error.message === 'A valid URL is required' || error.message.startsWith('Only HTTP')) {
      return res.status(422).json({ detail: error.message });
    }
    console.error('URL scan failed:', error.message);
    return res.status(500).json({ detail: `Phishing analysis failed: ${error.message}` });
  }
});

app.get('/dashboard/summary', (_req, res) => {
  const counts = db.prepare(`SELECT COUNT(*) AS total,
    SUM(CASE WHEN verdict = 'Safe' THEN 1 ELSE 0 END) AS safe,
    SUM(CASE WHEN verdict = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious,
    SUM(CASE WHEN verdict = 'High Risk' THEN 1 ELSE 0 END) AS high_risk,
    COUNT(DISTINCT url) AS unique_urls FROM url_scans`).get();
  res.json({ success: true, summary: { total_scans: counts.total, safe: counts.safe || 0, suspicious: counts.suspicious || 0,
    high_risk: counts.high_risk || 0, repeated_links: counts.total - counts.unique_urls } });
});
app.get('/dashboard-summary', (_req, res) => {
  const counts = db.prepare(`SELECT COUNT(*) AS total,
    SUM(CASE WHEN verdict = 'Safe' THEN 1 ELSE 0 END) AS safe,
    SUM(CASE WHEN verdict = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious,
    SUM(CASE WHEN verdict = 'High Risk' THEN 1 ELSE 0 END) AS high_risk,
    COUNT(DISTINCT url) AS unique_urls FROM url_scans`).get();
  res.json({ success: true, summary: { total_scans: counts.total, safe: counts.safe || 0, suspicious: counts.suspicious || 0,
    high_risk: counts.high_risk || 0, repeated_links: counts.total - counts.unique_urls } });
});
app.get('/scan-history', (_req, res) => {
  const scans = db.prepare('SELECT id, url, verdict, risk_score, risk_level, reason, advice, source, created_at FROM url_scans ORDER BY created_at DESC, id DESC').all();
  res.json(scans.map((scan) => ({ ...scan, scan_id: scan.id, reasons: (scan.reason || '').split(', ').filter(Boolean), last_scanned_at: scan.created_at })));
});

app.get('/webhook/whatsapp', (req, res) => {
  const { 'hub.mode': mode, 'hub.verify_token': token, 'hub.challenge': challenge } = req.query;
  if (mode === 'subscribe' && config.whatsappVerifyToken && token === config.whatsappVerifyToken) return res.type('text/plain').send(String(challenge || ''));
  return res.status(403).json({ detail: 'Verification failed' });
});

app.post('/webhook/whatsapp', async (req, res) => {
  if (!config.metaAppSecret && process.env.NODE_ENV === 'production') {
    return res.status(503).json({ detail: 'FB_APP_SECRET must be configured for production webhooks' });
  }
  if (config.metaAppSecret && !verifyMetaWebhookSignature(req.rawBody, req.get('X-Hub-Signature-256'), config.metaAppSecret)) {
    return res.status(401).json({ detail: 'Invalid webhook signature' });
  }
  const event = req.body;
  res.status(200).json({ success: true, received: true });
  void processWhatsAppWebhook(event).catch((error) => console.error('WhatsApp webhook processing failed:', error.message));
});

async function processWhatsAppWebhook(event) {
  for (const entry of event?.entry || []) {
    for (const change of entry.changes || []) {
      if (change.field && change.field !== 'messages') continue;
      const value = change.value || {};
      for (const status of value.statuses || []) recordWhatsAppStatus(status);
      for (const message of value.messages || []) {
        const sender = message.from;
        if (!sender) continue;
        if (message.id) {
          const inserted = db.prepare(`INSERT INTO whatsapp_inbound_messages (message_id, sender_id, status)
            VALUES (?, ?, 'processing') ON CONFLICT(message_id) DO UPDATE SET sender_id = excluded.sender_id,
            status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE whatsapp_inbound_messages.status = 'failed'`).run(message.id, sender);
          if (inserted.changes === 0) continue;
          await markWhatsAppMessageAsRead(message.id);
        }
        try {
          if (message.type !== 'text') {
            await sendWhatsAppMessage(sender, 'Please send a text message.\n\n🔍 Send a URL to scan\n📚 Learn about phishing\n🤖 Ask cybersecurity questions');
          } else {
            const text = (message.text?.body || '').trim();
            if (!text) continue;
            const reply = await processMessage(sender, text);
            const sent = await sendWhatsAppMessage(sender, reply);
            if (sent.error || sent.status >= 400) console.error('WhatsApp reply send failed:', sent.error);
          }
          if (message.id) db.prepare("UPDATE whatsapp_inbound_messages SET status = 'processed', updated_at = CURRENT_TIMESTAMP WHERE message_id = ?").run(message.id);
        } catch (error) {
          if (message.id) db.prepare("UPDATE whatsapp_inbound_messages SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE message_id = ?").run(message.id);
          console.error('WhatsApp message processing failed:', error.message);
        }
      }
    }
  }
}

app.post('/n8n/whatsapp', async (req, res) => {
  const receivedSecret = req.get('X-N8N-Secret') || '';
  const expected = config.n8nWebhookSecret;
  const authorized = expected && receivedSecret && Buffer.byteLength(expected) === Buffer.byteLength(receivedSecret)
    && timingSafeEqual(Buffer.from(expected), Buffer.from(receivedSecret));
  if (!authorized) return res.status(401).json({ detail: 'Unauthorized' });
  const sender = typeof req.body?.sender === 'string' ? req.body.sender.trim() : '';
  const text = typeof req.body?.text === 'string' ? req.body.text.trim() : '';
  const messageId = typeof req.body?.message_id === 'string' ? req.body.message_id.trim() : '';
  if (!sender || !text) return res.status(400).json({ detail: 'Sender and text are required' });
  try {
    const reply = await processMessage(sender, text);
    return res.json({ success: true, status: 'processed', sender, reply, ...(messageId ? { message_id: messageId } : {}) });
  } catch (error) {
    console.error('n8n processing failed:', error.message);
    return res.status(500).json({ detail: 'Message processing failed' });
  }
});

app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && 'body' in error) return res.status(400).json({ detail: 'Invalid JSON body' });
  console.error('Unhandled API error:', error.message);
  return res.status(500).json({ detail: 'Internal server error' });
});
