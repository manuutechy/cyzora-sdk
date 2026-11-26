import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import { Cyzora, CyzoraError, WebhookEvents, toCents } from '../dist/index.js';

const clientWith = (body, capture) => new Cyzora({
  secretKey: 'sk_live_x',
  webhookSecrets: ['whsec_a'],
  fetchImpl: async (url, init) => {
    capture.url = String(url);
    capture.init = init;
    return { ok: true, status: 200, text: async () => body };
  },
});

test('amounts round up to whole shillings and test events are known', () => {
  assert.equal(toCents(2500.4), 250100);
  assert.equal(WebhookEvents.WebhookTest, 'webhook.test');
});

test('charge payload, phone normalization and idempotency key', async () => {
  const capture = {};
  const client = clientWith('{"id":"chg_1"}', capture);
  await client.createCharge({
    amountKes: 2500.4, phone: '0712345678', network: 'tkash', idempotencyKey: 'INV-1',
  });
  assert.equal(capture.url, 'https://api.cyzora.co.ke/api/v1/charges');
  assert.deepEqual(JSON.parse(capture.init.body), {
    amount: 250100, phone: '254712345678', network: 'tkash',
  });
  assert.equal(capture.init.headers['Idempotency-Key'], 'INV-1');
});

test('payouts reject fractional shillings and incomplete destinations', async () => {
  const client = clientWith('{}', {});
  await assert.rejects(() => client.createPayout({ amountKes: 1500.5, phone: '0712345678' }), CyzoraError);
  await assert.rejects(() => client.createPayout({
    amountKes: 1500, destinationType: 'paybill', shortCode: '100000',
  }), CyzoraError);
});

test('fee preview uses destination and wallet query parameters', async () => {
  const capture = {};
  const client = clientWith('{}', capture);
  await client.payoutFeePreview(2500, 'paybill', 'collections');
  assert.equal(
    capture.url,
    'https://api.cyzora.co.ke/api/v1/payouts/fee-preview?amount=250000&destination=paybill&wallet=collections',
  );
});

test('statement verification is public and exports return raw CSV', async () => {
  const capture = {};
  const client = clientWith('{"valid":true}', capture);
  await client.verifyStatement('K7PX3MZQ9H2D');
  assert.equal(capture.url, 'https://api.cyzora.co.ke/api/v1/public/statements/verify/K7PX3MZQ9H2D');
  assert.equal(capture.init.headers['X-API-Key'], undefined);

  const csvClient = clientWith('date,amount\n2026-10-01,2500.00\n', {});
  assert.equal(await csvClient.exportCharges({ status: 'succeeded' }), 'date,amount\n2026-10-01,2500.00\n');
});

test('signature checks the exact bytes and event headers must agree', () => {
  const client = clientWith('{}', {});
  const raw = Buffer.from([0xff, 0xfe, 0x00, 0x7b]);
  const sig = createHmac('sha256', 'whsec_a').update(raw).digest('hex');
  assert.equal(client.verifyWebhookSignature(raw, sig), true);
  assert.equal(client.verifyWebhookSignature(raw, sig.toUpperCase()), false);

  const body = Buffer.from('{"event":"charge.succeeded"}');
  const bodySig = createHmac('sha256', 'whsec_a').update(body).digest('hex');
  assert.equal(client.constructWebhookEvent(body, bodySig, 'charge.succeeded').event, 'charge.succeeded');
  assert.throws(() => client.constructWebhookEvent(body, bodySig, 'payout.paid'), CyzoraError);
});
