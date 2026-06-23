# OWASP Top 10 Security Notes

Personal security notes built while studying OWASP Top 10:2025 and PortSwigger Web Security Academy.

Each topic includes attacker mindset, detection patterns, testing methodology, payloads, and prevention — written for both technical reference and general understanding.

## Topics

| # | Topic | Status |
|---|-------|--------|
| A01 | [Broken Access Control](./a01-broken-access-control/) | ✅ Done |
| A02 | [Security Misconfiguration](./a02-security-misconfiguration/) |  ✅ Done |
| A03 | [Software Supply Chain Failures](./a03-software-supply-chain-failures/index.md) | ✅ Done |
| A04 | [Cryptographic Failures](./a04-cryptographic-failures/index.md) | ✅ Done |
| A05 | [Injection](./a05-injection/index.md) | ✅ Done |
| A06 | Insecure Design | 🔄 In progress |
| A07 | [Authentication Failures](./a07-authentication-failures/index.md) | ✅ Done |
| A08 | Software or Data Integrity Failures | ⬜ Planned |
| A09 | Security Logging and Alerting Failures | ⬜ Planned |
| A10 | Mishandling of Exceptional Conditions | ⬜ Planned |

## Note structure

Each topic follows the same format:

- **Concept** — what it is and why it happens
- **Attack types** — breakdown of variants
- **Indicators** — how to spot it during testing
- **Attack flow** — step-by-step methodology
- **Payloads** — ready-to-use request examples
- **Prevention** — how to fix it (with code examples)
- **Labs** — PortSwigger labs to practice
- **Real-world cases** — examples from real applications

## Resources

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
