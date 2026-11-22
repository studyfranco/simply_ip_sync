# simply_ip_sync goals

`simply_ip_sync` ingests external threat feeds, extracts and normalizes IP addresses and CIDRs, and delivers batches to configured vaults. It also replicates deltas and tombstones between vaults at different sites. Operators can run ingestion and replication on a UTC cron schedule or trigger a run through the authenticated API.

Canonical IP state belongs to `simply_ip_vault`. This service retains job configuration, cursors, and operational logs. Its scope excludes direct host firewall changes and unauthenticated public feed endpoints.

## Ecosystem

In the six-service `simply_*` ecosystem, this service owns ingestion and replication. `simply_ip_vault` owns IP records and the API used for reads and writes. `simply_ip_exporter` handles export for downstream consumers, and `simply_hook_executor` handles authorized hook execution. Other ecosystem services consume or act on vault data independently of this daemon. The sync daemon's cross-service runtime contract is with the vault API.

## Network placement

- **`ext`** provides outbound HTTPS or HTTP access for downloading configured threat feeds, such as `https://feeds.example.org/threats.txt`.
- **`isolate`** is the internal Docker network used for authenticated vault reads and writes, such as `https://vault-site-a.example.test`. An optional reverse proxy can reach the admin UI over this network and expose it under the deployment's administrative access controls.

The daemon connects these networks at the application layer. It parses and applies feed policy before transmitting batches. Replication reads and forwards authorized deltas between configured vault endpoints.

## Security invariants

- CANONICAL_V1 HMAC authenticates API requests. The replay cache rejects duplicate signatures for 300 seconds.
- XChaCha20-Poly1305 seals stored signing secrets and vault credentials.
- Feed fetches apply SSRF controls and enforce bounds on payload size and archive decompression.
- RBAC scopes configuration, job triggers, and logs to authorized keys and resources.

Use documentation-only addresses such as `192.0.2.10`, `198.51.100.20`, and `203.0.113.30`, and reserved domains such as `vault-site-a.example.test`. Keep production endpoints, addresses, and credentials out of documentation.
