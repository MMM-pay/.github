# Security Policy

This is the organization-wide fallback policy for Payflow. Several repositories
have their own `SECURITY.md` with a scope section; that repository's policy
takes precedence over this one.

## Audit status

Unaudited. Testnet only. Do not connect a wallet holding real value.

## Reporting a vulnerability

Do not open a public issue for a security problem.

Use GitHub [private vulnerability reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on the affected repository (the **Security** tab → **Report a vulnerability**),
or email the maintainer listed in that repository's README. Acknowledgement
within 72 hours.

Report in the repository the problem lives in:

- Soroban contracts → [payflow-contract](https://github.com/MMM-pay/payflow-contract)
- Indexer, settlement keeper and REST API → [payflow-backend](https://github.com/MMM-pay/payflow-backend)
- Merchant dashboard and subscriber portal → [payflow-frontend](https://github.com/MMM-pay/payflow-frontend)

If you are not sure, report it on any Payflow repository and we will route it.

## Scope

In scope: anything that could move funds against a mandate's limits, cause a
user to sign a transaction other than the one shown to them, leak subscriber
data, or let an attacker bill without authorization.

Out of scope: vulnerabilities in third-party wallet extensions, denial of
service against public testnet infrastructure, and findings that require a
compromised build or deploy environment you already control.
