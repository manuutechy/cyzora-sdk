# Changelog

## 1.1.0

- Aligned all four clients with the local API documentation: added payout listing,
  charge CSV export, public statement verification, hosted checkout in Go, and payout
  channels and fee preview in Go.
- Corrected the fee preview query to use `destination` and `wallet`, and added wallet
  and webhook secret fallbacks to `CYZORA_PAYOUT_WALLET`, `CYZORA_API_BASE` and
  `CYZORA_WEBHOOK_SECRET`.
- Changed charge and checkout amounts to round odd cents up to the next shilling, and
  added validation that rejects fractional payout amounts and incomplete destinations.
- Added the `webhook.test` event, optional `X-Cyzora-Event` consistency checking, and
  raw-byte signature verification in TypeScript. Retries now also cover a 409 returned
  for a request with an idempotency key.
- Updated the README and examples to reflect flat webhook payloads, test-mode phones and
  the complete API surface. The local API PDF remains untracked.
