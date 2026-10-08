import test from 'node:test';
import assert from 'node:assert/strict';
import { checkEnvironment } from '../src/config.js';

test('environment accepts default port and optional service credentials', () => {
  assert.deepEqual(checkEnvironment({}), { ok: true, errors: [] });
});

test('environment rejects a non-numeric port', () => {
  const result = checkEnvironment({ PORT: 'eight-thousand' });
  assert.equal(result.ok, false);
  assert.match(result.errors[0], /PORT/);
});

test('environment rejects ports outside the TCP range', () => {
  assert.equal(checkEnvironment({ PORT: '65536' }).ok, false);
  assert.equal(checkEnvironment({ PORT: '0' }).ok, false);
});

test('environment validates access token expiry when configured', () => {
  assert.equal(checkEnvironment({ ACCESS_TOKEN_EXPIRE_MINUTES: '1440' }).ok, true);
  assert.equal(checkEnvironment({ ACCESS_TOKEN_EXPIRE_MINUTES: '0' }).ok, false);
});
