import { db } from './database.js';
import { analyzeUrl } from './detector.js';
import { sendWhatsAppMessage } from './integrations.js';

export async function scanUrlTask(url, source = 'background') {
  try {
    const result = await analyzeUrl(url);
    const reasonText = result.reasons.join(', ');
    const inserted = db.prepare(`INSERT INTO url_scans (url,result,verdict,risk_level,score,risk_score,reasons,reason,advice,source)
      VALUES (?,?,?,?,?,?,?,?,?,?)`).run(result.url, result.result, result.verdict, result.risk_level, result.score,
      result.risk_score, reasonText, reasonText, result.advice, source);
    return { status: 'completed', scan_id: Number(inserted.lastInsertRowid), url: result.url, verdict: result.verdict };
  } catch (error) {
    return { status: 'failed', error: error.message };
  }
}

export async function whatsappScanReplyTask(url, phoneNumber) {
  const result = await scanUrlTask(url, 'whatsapp_background');
  if (result.status !== 'completed') {
    await sendWhatsAppMessage(phoneNumber, 'Sorry, the link could not be scanned at the moment. Please try again later.');
    return result;
  }
  const scan = db.prepare('SELECT * FROM url_scans WHERE id = ?').get(result.scan_id);
  if (!scan) return { status: 'failed', error: 'Saved scan not found' };
  const message = `🔍 Phishing Scan Result\n\nURL: ${scan.url}\nVerdict: ${scan.verdict || scan.result}\nRisk Level: ${scan.risk_level}\nRisk Score: ${scan.risk_score ?? scan.score}\n\nAdvice: ${scan.advice || ''}`;
  await sendWhatsAppMessage(phoneNumber, message);
  return { status: 'reply_sent', scan_id: scan.id, phone_number: phoneNumber };
}
