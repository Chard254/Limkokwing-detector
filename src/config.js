import dotenv from 'dotenv';
import path from 'node:path';

dotenv.config({ path: process.env.ENV_FILE || '.env' });

const numberFromEnv = (name, fallback) => {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
};

const resolveSqlitePath = (value = './data/phishguard.sqlite') =>
  path.resolve(process.cwd(), value);

export const config = {
  port: numberFromEnv('PORT', 7779),
  sqlitePath: resolveSqlitePath(process.env.SQLITE_PATH),
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY || '',
  groqApiKey: process.env.GROQ_API_KEY || '',
  groqModel: process.env.GROQ_MODEL || 'openai/gpt-oss-120b',
  whatsappVerifyToken: process.env.WHATSAPP_VERIFY_TOKEN || '',
  whatsappAccessToken: process.env.WHATSAPP_PERMANENT_TOKEN
    || process.env.WHATSAPP_ACCESS_TOKEN
    || process.env.WHATSAPP_TOKEN
    || '',
  whatsappPhoneNumberId: process.env.WHATSAPP_PHONE_NUMBER_ID || '',
  metaAppSecret: process.env.FB_APP_SECRET || process.env.META_APP_SECRET || '',
  graphApiVersion: (process.env.GRAPH_API_VERSION || process.env.WHATSAPP_API_VERSION || 'v20.0').replaceAll('/', ''),
  n8nWebhookSecret: process.env.N8N_WEBHOOK_SECRET || '',
  jwtSecret: process.env.JWT_SECRET_KEY || '',
  jwtAlgorithm: process.env.JWT_ALGORITHM || 'HS256',
  accessTokenExpireMinutes: numberFromEnv('ACCESS_TOKEN_EXPIRE_MINUTES', 1440),
};

export function checkEnvironment(env = process.env) {
  const errors = [];
  const port = Number(env.PORT || 8000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push('PORT must be an integer from 1 to 65535');
  if (env.ACCESS_TOKEN_EXPIRE_MINUTES && (!Number.isInteger(Number(env.ACCESS_TOKEN_EXPIRE_MINUTES)) || Number(env.ACCESS_TOKEN_EXPIRE_MINUTES) < 1)) {
    errors.push('ACCESS_TOKEN_EXPIRE_MINUTES must be a positive integer');
  }
  return { ok: errors.length === 0, errors };
}

const environmentCheck = checkEnvironment();
if (!environmentCheck.ok) throw new Error(`Invalid environment configuration: ${environmentCheck.errors.join('; ')}`);
