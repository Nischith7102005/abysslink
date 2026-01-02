# Security Policy

AbyssLink is built on the principle of **absolute impermanence and anonymity**. We take security extremely seriously.

---

## 🛡️ Security Guarantees

- **No persistent storage**: Messages, files, and room data exist only in memory.
- **End-to-end encryption**: All messages and files encrypted in the client using AES-GCM; keys derived from room password + salt via PBKDF2.
- **Password never transmitted in plaintext**: Only used client-side for key derivation; server stores only `bcrypt` hash.
- **Strict rate limiting**: Prevents brute-force attacks on room access.
- **Automatic room expiry**: All data destroyed after 24 hours (or on manual vanish).
- **Hardened headers**: CSP, HSTS, X-Frame-Options, and more enforced on both frontend and backend.

---

## 🚨 Reporting a Vulnerability

We do **not** operate a public bug bounty program.

If you discover a security issue:

1. **Do not** disclose it publicly.
2. **Do not** attempt to access, extract, or retain any user data.
3. Email details to: `security [at] abysslink.systems` (PGP preferred).

Include:
- A clear description of the issue
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

We will acknowledge your report within **48 hours** and provide updates as we investigate.

> **Note**: AbyssLink stores **no logs** and **no user data**, so forensic evidence is limited.

---

## ❌ What Is Not a Vulnerability

- UI/UX issues without security impact
- Theoretical attacks requiring physical access or client compromise
- Social engineering (e.g., sharing password via insecure channel)
- Room key leakage (this is a user responsibility)

---

## 💀 Final Reminder

**Upon room expiration or destruction, all data is permanently and irrecoverably deleted.**  
There is no backup. There is no recovery. This is by design.

> *“Join the network that forgets.”*
