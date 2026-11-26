<?php
declare(strict_types=1);

use Cyzora\Client;
use Cyzora\CyzoraException;

require __DIR__ . '/../src/Client.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

check(Client::toCents(2500.4) === 250100, 'charges must round odd cents up');
check(Client::toPayoutCents(1500) === 150000, 'whole payout shillings');
check(Client::normalizePhone('0712345678') === '254712345678', 'phone normalization');
check(in_array('webhook.test', Client::WEBHOOK_EVENTS, true), 'webhook.test is a known event');

try {
    Client::toPayoutCents(1500.5);
    throw new RuntimeException('fractional payout should be refused');
} catch (CyzoraException $e) {
    check(strpos($e->getMessage(), 'whole shillings') !== false, 'payout error message');
}

putenv('CYZORA_API_BASE=https://example.test/api/v1/');
putenv('CYZORA_WEBHOOK_SECRET=whsec_a, whsec_b');
$client = new Client('sk_live_x');
$base = (new ReflectionProperty(Client::class, 'baseUrl'));
$base->setAccessible(true);
$secrets = (new ReflectionProperty(Client::class, 'webhookSecrets'));
$secrets->setAccessible(true);
check($base->getValue($client) === 'https://example.test/api/v1', 'base URL from environment');
check($secrets->getValue($client) === ['whsec_a', 'whsec_b'], 'webhook secrets from environment');

$raw = "\xff\xfe{\"event\":\"charge.succeeded\"}";
check($client->verifyWebhookSignature($raw, hash_hmac('sha256', $raw, 'whsec_b')), 'signature covers raw bytes');

$jsonRaw = '{"event":"charge.succeeded","note":"café"}';
$sig = hash_hmac('sha256', $jsonRaw, 'whsec_b');
check($client->constructWebhookEvent($jsonRaw, $sig, 'charge.succeeded')['event'] === 'charge.succeeded', 'event header matches');
try {
    $client->constructWebhookEvent($jsonRaw, $sig, 'payout.paid');
    throw new RuntimeException('mismatched event header should be refused');
} catch (CyzoraException $e) {
    check($e->status === 400, 'event mismatch status');
}

try {
    $client->createCharge(250, 'not-a-phone');
    throw new RuntimeException('invalid phone should be refused');
} catch (CyzoraException $e) {
    check(strpos($e->getMessage(), 'M-Pesa') !== false, 'phone error message');
}

try {
    $client->createPayout(29, ['phone' => '0712345678']);
    throw new RuntimeException('payout below minimum should be refused');
} catch (CyzoraException $e) {
    check(strpos($e->getMessage(), 'KES 30') !== false, 'minimum error message');
}

try {
    $client->createPayout(1500, ['destinationType' => 'paybill', 'shortCode' => '100000']);
    throw new RuntimeException('paybill without account reference should be refused');
} catch (CyzoraException $e) {
    check(strpos($e->getMessage(), 'accountRef') !== false, 'destination error message');
}

echo "PHP SDK tests passed\n";
