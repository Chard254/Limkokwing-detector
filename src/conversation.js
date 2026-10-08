import { db } from './database.js';
import { askGroq } from './integrations.js';
import { analyzeUrl, extractUrl, normalizeScanResult } from './detector.js';

function saveMessage(phone, role, message) {
  db.prepare('INSERT INTO conversations (phone_number, role, message) VALUES (?, ?, ?)').run(phone, role, message);
}

function getState(phone) {
  db.prepare('INSERT OR IGNORE INTO conversation_states (phone_number) VALUES (?)').run(phone);
  return db.prepare('SELECT * FROM conversation_states WHERE phone_number = ?').get(phone);
}

function updateState(phone, state) {
  db.prepare("UPDATE conversation_states SET state = ?, updated_at = CURRENT_TIMESTAMP WHERE phone_number = ?").run(state, phone);
}

function saveScan(result, source = 'whatsapp') {
  const reasonText = result.reasons.join(', ');
  const created = db.prepare(`INSERT INTO url_scans (url,result,verdict,risk_level,score,risk_score,reasons,reason,advice,source)
    VALUES (@url,@verdict,@verdict,@risk_level,@risk_score,@risk_score,@reasons,@reasons,@advice,@source)`)
    .run({ url: result.url, verdict: result.verdict, risk_level: result.risk_level,
      risk_score: result.risk_score, reasons: reasonText, advice: result.advice, source });
  return Number(created.lastInsertRowid);
}

function scanReply(result) {
  const reasons = result.reasons.slice(0, 5).map((reason) => `• ${reason}`).join('\n') || '• No major suspicious signs found';
  return `🔍 Phishing Scan Result\n\nURL:\n${result.url}\n\nVerdict:\n${result.verdict}\n\nRisk Level:\n${result.risk_level}\n\nRisk Score:\n${result.risk_score}\n\nReasons:\n\n${reasons}\n\nAdvice:\n\n${result.advice}`;
}

function learnMenu() {
  return '📚 Learn More\n\nReply:\n1️⃣ Explain this result\n2️⃣ What is phishing?\n3️⃣ How do I protect myself?\n4️⃣ WhatsApp scams\n5️⃣ Scan another URL';
}

async function processUrl(phone, url) {
  const result = normalizeScanResult(url, await analyzeUrl(url));
  saveScan(result);
  const explanation = await askGroq([
    { role: 'system', content: 'Explain these phishing scan results without changing the detector verdict. Educate the user.' },
    { role: 'user', content: `URL: ${result.url}\nVerdict: ${result.verdict}\nRisk: ${result.risk_level}\nReasons: ${result.reasons.join(', ')}\nAdvice: ${result.advice}` },
  ]);
  updateState(phone, 'LEARNING_MENU');
  return `${scanReply(result)}\n\n━━━━━━━━━━━━━━━━━━\n\n🤖 AI Explanation\n\n${explanation}\n\n━━━━━━━━━━━━━━━━━━\n\n${learnMenu()}`;
}

function lastUserUrl(phone) {
  const rows = db.prepare("SELECT message FROM conversations WHERE phone_number = ? AND role = 'user' ORDER BY created_at DESC, id DESC LIMIT 50").all(phone);
  for (const row of rows) { const url = extractUrl(row.message); if (url) return url; }
  return null;
}

async function menuReply(phone, option) {
  const menus = {
    '2': '📚 What is phishing?\n\nPhishing is an attack where criminals pretend to be trusted companies or people to steal passwords, bank details, one-time codes, or personal information.',
    '3': '🛡 How to protect yourself online:\n\n✅ Check links before clicking\n✅ Never share one-time codes\n✅ Use two-factor authentication\n✅ Avoid unknown attachments\n✅ Verify suspicious messages',
    '4': '📱 Common WhatsApp scams include fake jobs, lottery winnings, verification code requests, fake support, and family emergency messages. Never share your WhatsApp verification code.',
    '5': '🔍 Send me another URL and I will scan it for you.',
  };
  if (option === '1') {
    const url = lastUserUrl(phone);
    return url ? processUrl(phone, url) : '⚠️ I could not find a previous URL to scan. Please send a URL first, for example https://example.com';
  }
  return menus[option] || `Please select an option:\n\n1️⃣ Explain this result\n2️⃣ What is phishing?\n3️⃣ How do I protect myself?\n4️⃣ WhatsApp scams\n5️⃣ Scan another URL`;
}

export async function processMessage(phone, text) {
  const message = String(text || '').trim();
  if (!message) return 'Please send a message.';
  saveMessage(phone, 'user', message);
  const state = getState(phone);
  let reply;
  try {
    if (state.state === 'LEARNING_MENU') reply = await menuReply(phone, message);
    else {
      const url = extractUrl(message);
      if (url) reply = await processUrl(phone, url);
      else {
        const history = db.prepare('SELECT role, message AS content FROM conversations WHERE phone_number = ? ORDER BY created_at ASC, id ASC LIMIT 20').all(phone);
        reply = await askGroq([...history.slice(0, -1), { role: 'user', content: message }]);
      }
    }
  } catch (error) {
    console.error('Conversation processing failed:', error.message);
    reply = 'Sorry, I encountered an error.';
  }
  saveMessage(phone, 'assistant', reply);
  return reply;
}
