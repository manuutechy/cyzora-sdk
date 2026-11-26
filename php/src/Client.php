<?php
declare(strict_types=1);

namespace Cyzora;

/**
 * Cyzora SDK for PHP 7.4+ (uses cURL; no external dependencies).
 *
 * Cyzora is an M-Pesa payment rail. Amounts on the wire are integer cents of
 * whole shillings (KES 2,500 -> 250000). Every money-moving POST should carry an
 * idempotency key so a retry cannot double-charge or double-pay.
 *
 *   $cyzora = new \Cyzora\Client('sk_live_...', ['webhookSecret' => 'whsec_...']);
 *   $charge = $cyzora->createCharge(100, '0712345678', ['accountRef' => 'INV-1', 'idempotencyKey' => 'INV-1']);
 */

class CyzoraException extends \RuntimeException
{
    public ?int $status = null;
    public $body = null;

    public function __construct(string $message, ?int $status = null, $body = null)
    {
        parent::__construct($message);
        $this->status = $status;
        $this->body = $body;
    }
}

class Client
{
    public const DEFAULT_BASE_URL = 'https://api.cyzora.co.ke/api/v1';
    public const PAYOUT_MIN_CENTS = 3000; // KES 30

    /** Known webhook event names. The rail evolves, so also compare raw event strings. */
    public const WEBHOOK_EVENTS = [
        'charge.succeeded', 'charge.failed', 'charge.expired', 'payout.paid', 'payout.failed',
        'webhook.test',
    ];

    private string $secretKey;
    private string $baseUrl;
    /** @var string[] */
    private array $webhookSecrets;
    private int $timeout;
    private int $maxRetries;

    /**
     * @param array{baseUrl?:string, webhookSecret?:string|string[], timeout?:int} $options
     */
    public function __construct(string $secretKey, array $options = [])
    {
        if ($secretKey === '') {
            throw new CyzoraException('secretKey is required');
        }
        $this->secretKey = $secretKey;
        $baseUrl = $options['baseUrl'] ?? (getenv('CYZORA_API_BASE') ?: self::DEFAULT_BASE_URL);
        $this->baseUrl = rtrim((string)$baseUrl, '/');
        $this->timeout = (int)($options['timeout'] ?? 30);
        $this->maxRetries = (int)($options['maxRetries'] ?? 2);
        $ws = $options['webhookSecret'] ?? null;
        if ($ws === null) {
            $configured = getenv('CYZORA_WEBHOOK_SECRET');
            $this->webhookSecrets = $configured ? array_values(array_filter(array_map('trim', explode(',', $configured)))) : [];
        } elseif (is_array($ws)) {
            $this->webhookSecrets = array_values(array_filter($ws));
        } else {
            $this->webhookSecrets = [$ws];
        }
    }

    // -- helpers ----------------------------------------------------------
    public static function normalizePhone(string $phone): ?string
    {
        $p = preg_replace('/[\s\-+]/', '', $phone) ?? '';
        if ($p === '') {
            return null;
        }
        if ($p[0] === '0') {
            $p = '254' . substr($p, 1);
        } elseif ($p[0] === '7' || $p[0] === '1') {
            $p = '254' . $p;
        }
        return preg_match('/^254[17]\d{8}$/', $p) === 1 ? $p : null;
    }

    /** Round up to the next whole shilling, as the rail does for charges and checkout. */
    public static function toCents($amountKes): int
    {
        $kes = (int)ceil((float)$amountKes);
        if ($kes < 1) {
            throw new CyzoraException('Amount must be at least KES 1.');
        }
        return $kes * 100;
    }

    /** Payouts are refused unless the amount is a whole number of shillings. */
    public static function toPayoutCents($amountKes, ?int $amountCents = null): int
    {
        $cents = $amountCents !== null ? (float)$amountCents : (float)$amountKes * 100;
        if (floor($cents) != $cents || (int)$cents % 100 !== 0) {
            throw new CyzoraException('Payout amounts must be whole shillings (a multiple of 100 cents).');
        }
        if ($cents < 1) {
            throw new CyzoraException('Amount must be at least KES 1.');
        }
        return (int)$cents;
    }

    public static function fromCents($cents): float
    {
        return round((float)($cents ?: 0)) / 100;
    }

    // -- transport --------------------------------------------------------
    /**
     * @param array<string,mixed>|null $body
     * @param array<string,mixed>|null $query
     * @param bool $auth Send the secret key; public endpoints need no key.
     * @param bool $raw Return the response text (CSV exports) instead of decoded JSON.
     * @return array<string,mixed>|string
     */
    private function request(string $path, string $method = 'GET', ?array $body = null, ?string $idempotencyKey = null, ?array $query = null, bool $auth = true, bool $raw = false)
    {
        $url = $this->baseUrl . $path;
        if ($query) {
            $clean = array_filter($query, static fn($v) => $v !== null && $v !== '');
            if ($clean) {
                $url .= '?' . http_build_query($clean);
            }
        }
        $headers = ['Accept: application/json'];
        if ($auth) {
            $headers[] = 'X-API-Key: ' . $this->secretKey;
        }
        $payload = null;
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
            $payload = json_encode($body);
        }
        if ($idempotencyKey) {
            $headers[] = 'Idempotency-Key: ' . substr((string)$idempotencyKey, 0, 128);
        }

        $ch = curl_init($url);
        if ($ch === false) {
            throw new CyzoraException('Could not initialize cURL');
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $this->timeout,
        ]);
        if ($payload !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        }
        // Retrying is only safe when the rail can dedupe: GETs, or POSTs with an idempotency key.
        $canRetry = strtoupper($method) === 'GET' || $idempotencyKey !== null;
        $attempt = 0;
        while (true) {
            $response = curl_exec($ch);
            if ($response === false) {
                $err = curl_error($ch);
                if ($canRetry && $attempt < $this->maxRetries) { $attempt++; usleep((int)(250000 * (2 ** ($attempt - 1)))); continue; }
                curl_close($ch);
                throw new CyzoraException('Could not reach Cyzora: ' . $err);
            }
            $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $data = [];
            $text = (string)$response;
            if ($text !== '') {
                $decoded = json_decode($text, true);
                $data = is_array($decoded) ? $decoded : ['raw' => $text];
            }
            if ($status < 200 || $status >= 300) {
                // A 409 with an idempotency key means the first request is still
                // being processed; the docs advise waiting and retrying with it.
                $transient = $status >= 500 || $status === 429 || ($status === 409 && $idempotencyKey !== null);
                if ($transient && $canRetry && $attempt < $this->maxRetries) { $attempt++; usleep((int)(250000 * (2 ** ($attempt - 1)))); continue; }
                curl_close($ch);
                $msg = $data['error'] ?? $data['message'] ?? ('Cyzora request failed (' . $status . ')');
                throw new CyzoraException((string)$msg, $status, $data);
            }
            curl_close($ch);
            return $raw ? $text : $data;
        }
    }

    /**
     * Escape hatch for any endpoint, including new ones the rail adds before this
     * SDK ships a typed wrapper. $path is appended to the base URL.
     *
     * @param array<string,mixed>|null $body
     * @param array<string,mixed>|null $query
     * @return array<string,mixed>|string
     */
    public function rawRequest(string $method, string $path, ?array $body = null, ?string $idempotencyKey = null, ?array $query = null, bool $auth = true, bool $raw = false)
    {
        return $this->request($path, $method, $body, $idempotencyKey, $query, $auth, $raw);
    }

    // -- charges ----------------------------------------------------------
    /**
     * @param array{network?:string, accountRef?:string, description?:string, metadata?:array<string,mixed>, idempotencyKey?:string, amountCents?:int} $options
     * @return array<string,mixed>
     */
    public function createCharge($amountKes, string $phone, array $options = []): array
    {
        $normalized = self::normalizePhone($phone);
        if ($normalized === null) {
            throw new CyzoraException('Enter a valid M-Pesa phone number (e.g. 0712 345 678).');
        }
        $cents = isset($options['amountCents']) ? (int)(ceil((float)$options['amountCents'] / 100) * 100) : self::toCents($amountKes);
        if ((int)$cents < 100) {
            throw new CyzoraException('Amount must be a whole number of shillings, at least KES 1.');
        }
        $body = [
            'amount' => (int)$cents,
            'phone' => $normalized,
            'network' => $options['network'] ?? 'mpesa',
        ];
        if (!empty($options['accountRef'])) {
            $body['account_ref'] = substr((string)$options['accountRef'], 0, 64);
        }
        if (!empty($options['description'])) {
            $body['description'] = substr((string)$options['description'], 0, 200);
        }
        if (!empty($options['metadata'])) {
            $body['metadata'] = $options['metadata'];
        }
        return $this->request('/charges', 'POST', $body, $options['idempotencyKey'] ?? null);
    }

    /** @return array<string,mixed> */
    public function getCharge(string $chargeId): array
    {
        return $this->request('/charges/' . rawurlencode($chargeId));
    }

    /** Download charges as CSV; from/to are dates such as 2026-10-01. */
    public function exportCharges(?array $query = null): string
    {
        return (string)$this->request('/charges/export', 'GET', null, null, $query, true, true);
    }

    /**
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    public function createCheckoutSession($amountKes, array $options = []): array
    {
        $body = ['amount' => self::toCents($amountKes)];
        foreach ([
            'accountRef' => 'account_ref', 'description' => 'description', 'callbackUrl' => 'callback_url',
            'cancelUrl' => 'cancel_url', 'customerEmail' => 'customer_email', 'metadata' => 'metadata',
        ] as $opt => $field) {
            if (isset($options[$opt])) {
                $body[$field] = $options[$opt];
            }
        }
        if (!empty($options['customerPhone'])) {
            $body['customer_phone'] = self::normalizePhone((string)$options['customerPhone']) ?? $options['customerPhone'];
        }
        if (isset($options['expiresIn'])) {
            $body['expires_in'] = (int)$options['expiresIn'];
        }
        return $this->request('/transactions/initialize', 'POST', $body, $options['idempotencyKey'] ?? null);
    }

    /** @return array<string,mixed> */
    public function verifyTransaction(string $reference): array
    {
        return $this->request('/transactions/verify/' . rawurlencode($reference));
    }

    // -- payouts ----------------------------------------------------------
    /**
     * @param array{amountCents?:int, wallet?:string, channelId?:string, destinationType?:string, phone?:string, shortCode?:string, accountRef?:string, bankCode?:string, accountNumber?:string, accountName?:string, idempotencyKey?:string} $options
     * @return array<string,mixed>
     */
    public function createPayout($amountKes, array $options = []): array
    {
        $cents = self::toPayoutCents($amountKes, $options['amountCents'] ?? null);
        if ($cents < self::PAYOUT_MIN_CENTS) {
            throw new CyzoraException('The smallest payout is KES 30.');
        }
        $body = ['amount' => $cents];
        $wallet = $options['wallet'] ?? (getenv('CYZORA_PAYOUT_WALLET') ?: null);
        if ($wallet) {
            $body['wallet'] = $wallet;
        }
        if (!empty($options['channelId'])) {
            $body['channel_id'] = $options['channelId'];
        } else {
            $type = $options['destinationType'] ?? 'mobile';
            $body['destination_type'] = $type;
            $require = static function (string $field, $value) use ($type): void {
                if ($value === null || $value === '') {
                    throw new CyzoraException($field . ' is required for ' . $type . ' payouts.');
                }
            };
            if ($type === 'mobile') {
                $phone = self::normalizePhone((string)($options['phone'] ?? ''));
                if ($phone === null) {
                    throw new CyzoraException('phone must be a valid M-Pesa number for mobile payouts.');
                }
                $body['phone'] = $phone;
            } elseif ($type === 'till') {
                $require('shortCode', $options['shortCode'] ?? null);
                $body['short_code'] = $options['shortCode'];
            } elseif ($type === 'paybill') {
                $require('shortCode', $options['shortCode'] ?? null);
                $require('accountRef', $options['accountRef'] ?? null);
                $body['short_code'] = $options['shortCode'];
                $body['account_ref'] = $options['accountRef'];
            } elseif ($type === 'bank') {
                $require('bankCode', $options['bankCode'] ?? null);
                $require('accountNumber', $options['accountNumber'] ?? null);
                $require('accountName', $options['accountName'] ?? null);
                $body['bank_code'] = $options['bankCode'];
                $body['account_number'] = $options['accountNumber'];
                $body['account_name'] = $options['accountName'];
            } else {
                throw new CyzoraException('destinationType must be mobile, till, paybill or bank.');
            }
        }
        return $this->request('/payouts', 'POST', $body, $options['idempotencyKey'] ?? null);
    }

    /** @return array<string,mixed> */
    public function getPayout(string $payoutId): array
    {
        return $this->request('/payouts/' . rawurlencode($payoutId));
    }

    /** @return array<string,mixed> */
    public function listPayouts(?array $query = null): array
    {
        return $this->request('/payouts', 'GET', null, null, $query);
    }

    /** @return array<string,mixed> */
    public function getWallets(): array
    {
        return $this->request('/wallets');
    }

    /** @return array<string,mixed> */
    public function listPayoutChannels(): array
    {
        return $this->request('/payout-channels');
    }

    /** @return array<string,mixed> */
    public function listPayoutBanks(): array
    {
        return $this->request('/payout-banks');
    }

    /** Preview the fee using the rail's `destination` parameter and the payout wallet. */
    public function payoutFeePreview($amountKes, string $destinationType = 'mobile', ?string $wallet = null): array
    {
        return $this->request('/payouts/fee-preview', 'GET', null, null, [
            'amount' => self::toPayoutCents($amountKes), 'destination' => $destinationType, 'wallet' => $wallet,
        ]);
    }

    /** Verify a 12-character statement code; this public endpoint needs no API key. */
    public function verifyStatement(string $code): array
    {
        return $this->request('/public/statements/verify/' . rawurlencode($code), 'GET', null, null, null, false);
    }

    // -- webhooks ---------------------------------------------------------
    /**
     * Verify a webhook signature. $rawBody must be the exact bytes received and
     * $signature the X-Cyzora-Signature header (hex HMAC-SHA256). Returns true if it
     * matches any configured webhook secret (timing-safe).
     */
    public function verifyWebhookSignature(string $rawBody, ?string $signature): bool
    {
        if ($this->webhookSecrets === [] || !$signature || $rawBody === '') {
            return false;
        }
        $sig = trim($signature);
        foreach ($this->webhookSecrets as $secret) {
            $expected = hash_hmac('sha256', $rawBody, $secret);
            if (hash_equals($expected, $sig)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Verify the signature (against every configured secret) and parse the body in
     * one call. Throws CyzoraException if the signature is invalid or the body is
     * not JSON. $rawBody must be the exact bytes received.
     *
     * @return array<string,mixed>
     */
    public function constructWebhookEvent(string $rawBody, ?string $signature, ?string $eventHeader = null): array
    {
        if (!$this->verifyWebhookSignature($rawBody, $signature)) {
            throw new CyzoraException('Webhook signature verification failed', 401);
        }
        $decoded = json_decode($rawBody, true);
        if (!is_array($decoded)) {
            throw new CyzoraException('Webhook body is not valid JSON', 400);
        }
        if ($eventHeader !== null && $eventHeader !== '' && ($decoded['event'] ?? null) !== $eventHeader) {
            throw new CyzoraException('Webhook event header does not match the body', 400);
        }
        return $decoded;
    }
}
