# Payflow

**Pull-based recurring payments on Stellar.**

Stellar payments are push-only: the account holding the funds must sign every
transfer, so a merchant cannot bill a customer monthly without holding their
funds or their keys. Payflow adds the missing primitive, a **mandate**. A
subscriber signs once to authorize a fixed amount per period, optionally
capped, and can pause or cancel at any time. When a charge falls due, anyone
can settle it, and nobody can take more than the mandate allows.

**Try it:** [live demo on testnet](https://mmm-pay.github.io/payflow-frontend/) ·
[documentation](https://mmm-pay.github.io/payflow-docs/)

| Repository | What it is |
|---|---|
| [payflow-contract](https://github.com/MMM-pay/payflow-contract) | Soroban contracts (Rust): plan registry, subscriber vault, subscription billing |
| [payflow-backend](https://github.com/MMM-pay/payflow-backend) | Event indexer, settlement keeper and REST API (TypeScript) |
| [payflow-frontend](https://github.com/MMM-pay/payflow-frontend) | Merchant dashboard and subscriber portal (Next.js) |
| [payflow-docs](https://github.com/MMM-pay/payflow-docs) | Protocol design, guides and reference |

### Guarantees for subscribers

- The price, period and fee are frozen into the mandate when it is opened.
- A charge cap ends the mandate automatically.
- Cancelling is immediate and needs nobody's permission.
- Funds wait in a vault the subscriber can empty at any time.
- A keeper outage delays billing; it never builds up a backlog to drain at once.

### Contributing

Each code repository has scoped issues labelled by complexity
(`complexity:trivial`, `complexity:medium`, `complexity:high`) and a
`good-first-issue` label. Comment on an issue before starting so two people do
not build the same thing.

Unaudited and testnet only. Licensed Apache-2.0.
