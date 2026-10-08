import { config } from './config.js';
import { db } from './database.js';

function recordAcceptedMessage(messageId, recipient) {
  if (!messageId) return;
  db.prepare(`INSERT INTO whatsapp_message_statuses (message_id, recipient_id, status)
    VALUES (?, ?, 'accepted') ON CONFLICT(message_id) DO UPDATE SET recipient_id = excluded.recipient_id,
    status = CASE WHEN whatsapp_message_statuses.status IN ('delivered','read','failed','deleted')
      THEN whatsapp_message_statuses.status ELSE 'accepted' END, updated_at = CURRENT_TIMESTAMP`).run(messageId, recipient);
}

export function recordWhatsAppStatus(status) {
  if (!status?.id || !status?.status) return;
  const rank = { accepted: 0, sent: 1, delivered: 2, read: 3, failed: 4, deleted: 4 };
  const current = db.prepare('SELECT status FROM whatsapp_message_statuses WHERE message_id = ?').get(status.id);
  if (current && (rank[status.status] ?? 1) < (rank[current.status] ?? 1)) return;
  const firstError = status.errors?.[0] || {};
  db.prepare(`INSERT INTO whatsapp_message_statuses (message_id, recipient_id, status, timestamp, error_code, error_title)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(message_id) DO UPDATE SET
    recipient_id = excluded.recipient_id, status = excluded.status, timestamp = excluded.timestamp,
    error_code = excluded.error_code, error_title = excluded.error_title, updated_at = CURRENT_TIMESTAMP`)
    .run(status.id, String(status.recipient_id || ''), status.status, status.timestamp ? new Date(Number(status.timestamp) * 1000).toISOString() : null,
      firstError.code || null, firstError.title || firstError.message || null);
}

export async function sendWhatsAppMessage(to, message, previewUrl = false) {
  if (!config.whatsappAccessToken) return { error: 'Missing WhatsApp token' };
  if (!config.whatsappPhoneNumberId) return { error: 'Missing phone number ID' };
  const body = String(message).length > 4000 ? `${String(message).slice(0, 3900)}\n\n...` : String(message);
  try {
    const response = await fetch(`https://graph.facebook.com/${config.graphApiVersion}/${config.whatsappPhoneNumberId}/messages`, {
      method: 'POST', headers: { authorization: `Bearer ${config.whatsappAccessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ messaging_product: 'whatsapp', to, type: 'text', text: { body, preview_url: Boolean(previewUrl) } }),
      signal: AbortSignal.timeout(20000),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) return { status: response.status, error: data };
    recordAcceptedMessage(data.messages?.[0]?.id, to);
    return { ...data, http_status: response.status };
  } catch (error) { return { error: error.message }; }
}

export async function sendWhatsAppTemplate(to, templateName, languageCode = 'en_US') {
  if (!config.whatsappAccessToken) return { error: 'Missing WhatsApp token' };
  if (!config.whatsappPhoneNumberId) return { error: 'Missing phone number ID' };
  if (!templateName) return { error: 'A WhatsApp template name is required' };
  try {
    const response = await fetch(`https://graph.facebook.com/${config.graphApiVersion}/${config.whatsappPhoneNumberId}/messages`, {
      method: 'POST', headers: { authorization: `Bearer ${config.whatsappAccessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ messaging_product: 'whatsapp', to, type: 'template', template: { name: templateName, language: { code: languageCode } } }),
      signal: AbortSignal.timeout(20000),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) return { status: response.status, error: data };
    recordAcceptedMessage(data.messages?.[0]?.id, to);
    return { ...data, http_status: response.status };
  } catch (error) { return { error: error.message }; }
}

export async function markWhatsAppMessageAsRead(messageId) {
  if (!config.whatsappAccessToken || !config.whatsappPhoneNumberId) return { error: 'Missing WhatsApp credentials' };
  try {
    const response = await fetch(`https://graph.facebook.com/${config.graphApiVersion}/${config.whatsappPhoneNumberId}/messages`, {
      method: 'POST', headers: { authorization: `Bearer ${config.whatsappAccessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ messaging_product: 'whatsapp', status: 'read', message_id: messageId }), signal: AbortSignal.timeout(20000),
    });
    const data = await response.json().catch(() => ({}));
    return response.ok ? data : { status: response.status, error: data };
  } catch (error) { return { error: error.message }; }
}

export async function askGroq(messages) {
  if (!config.groqApiKey) return 'I can help explain cybersecurity topics. An AI response is unavailable because GROQ_API_KEY is not configured.';
  try {
    const { default: Groq } = await import('groq-sdk');
    const client = new Groq({ apiKey: config.groqApiKey });
    const systemPrompt = `You are PhishGuard AI. Explain cybersecurity clearly and simply. Focus on phishing, scams, suspicious websites, passwords, malware, fraud, and safe browsing. Never invent facts; say when unsure. Keep answers concise and educational.`;
    const conversation = [{ role: 'system', content: systemPrompt }, ...messages.filter((message) => message.role !== 'system')];
    const response = await client.chat.completions.create({ model: config.groqModel, messages: conversation, temperature: 0.3, max_completion_tokens: 700, top_p: 1 });
    return response.choices?.[0]?.message?.content?.trim() || 'Sorry, I could not prepare a reply.';
  } catch (error) {
    console.error('Groq API error:', error.message);
    return 'Sorry, I could not process your request at the moment. Please try again in a few moments.';
  }
}
