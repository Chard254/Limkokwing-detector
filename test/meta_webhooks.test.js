import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { verifyMetaWebhookSignature } from '../src/meta_webhooks.js';

test('accepts a matching Meta SHA-256 webhook signature', () => {
  const secret = 'test-app-secret';
  const body = Buffer.from('{"object":"whatsapp_business_account"}');
  const signature = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
  assert.equal(verifyMetaWebhookSignature(body, signature, secret), true);
});

test('rejects a signature for a different payload', () => {
  const secret = 'test-app-secret';
  const signature = `sha256=${createHmac('sha256', secret).update('payload-a').digest('hex')}`;
  assert.equal(verifyMetaWebhookSignature(Buffer.from('payload-b'), signature, secret), false);
});

test('rejects missing or malformed signature inputs', () => {
  assert.equal(verifyMetaWebhookSignature(Buffer.from('{}'), '', 'secret'), false);
  assert.equal(verifyMetaWebhookSignature(Buffer.from('{}'), 'sha1=abc', 'secret'), false);
  assert.equal(verifyMetaWebhookSignature(Buffer.from('{}'), 'sha256=abc', 'secret'), false);
  assert.equal(verifyMetaWebhookSignature(Buffer.from('{}'), 'sha256=' + 'a'.repeat(64), ''), false);
});
