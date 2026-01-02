# AbyssLink — Ephemeral Encrypted Chat

> *“In the modern digital landscape, surveillance is the default. We have built a system where privacy is the baseline.”*

AbyssLink is a zero-persistence, invite-only, end-to-end encrypted chat platform for professionals who demand absolute anonymity and impermanence in digital communication.

- 🔒 **End-to-end encrypted** messaging and file sharing (AES-GCM + PBKDF2)
- 🕵️ **No accounts, no usernames, no tracking** — every participant is anonymous
- ⏳ **Auto-destructing rooms** (24-hour expiry) with manual vanish capability
- 🚫 **Zero logs, zero storage** — messages vanish after delivery
- 🛡️ **Hardened by design** — rate limiting, input sanitization, strict CSP

---

## 🌐 Production Deployment Only

**AbyssLink is a hosted-only application. It cannot be run locally.**

- **Frontend**: Deployed on [Vercel](https://vercel.com)  
  → https://abysslink.vercel.app
- **Backend**: Deployed on [Render](https://render.com) (Docker-based)  
  → https://abysslink.onrender.com

The system is architected for **ephemeral, production-only operation**:
- No local development mode
- No database or persistent state
- Secrets, keys, and room data exist only in-memory during runtime
- Security headers, CSP, and rate-limiting are enforced exclusively in production

There is no supported way to self-host or test locally — by design.

---

## 🔐 How It Works

1. A user creates a room via the frontend, setting a **password** (never sent to the server in plaintext).
2. The room ID and password are shared **out-of-band** with invitees.
3. All chat messages and files are **encrypted in the browser** using a key derived from the password.
4. The backend only relays encrypted payloads — it **never sees plaintext**.
5. After 24 hours (or manual vanish), the room and all its data are **permanently destroyed** from memory.

The server stores only a `bcrypt` hash of the room password for access control — nothing else.

---

## 📜 License

Proprietary. For authorized use only.  
© 2025 AbyssLink Systems. All rights reserved.

> **No data stored. No exceptions.**
