Thank you for your interest in AbyssLink. Due to the sensitive nature of this project, contributions are **strictly limited** to authorized maintainers.

> ** Warning**: This is a security-critical system. Unauthorized modifications may compromise user anonymity.


## 🚫 Public Contributions

At this time, **we do not accept public pull requests, feature requests, or issue reports** via GitHub.

If you believe you've discovered a vulnerability, please follow the process outlined in [`SECURITY.md`](SECURITY.md).

---

## ✅ Internal Development Guidelines

### 1. **Security First**
- Never log, store, or transmit plaintext secrets.
- All user input must be sanitized or validated.
- Avoid side-channel leaks (e.g., timing differences in auth).

### 2. **Zero Persistence Principle**
- No database.
- No filesystem writes beyond temporary encrypted uploads.
- All data must be purged on room expiry or server shutdown.

### 3. **Code Style**
- Use `eslint` (not configured yet — follow existing patterns).
- Prefer native Node.js modules over third-party deps.
- Minimize client-side dependencies (currently: Socket.IO + GSAP).

### 4. **Testing**
- Manually verify:
  - Room creation + join flow
  - Message encryption/decryption
  - File upload + encryption
  - Vanish and expiry behaviors
  - Rate limiting under load

### 5. **Deployment**
- Backend: Push to `main` → auto-deploys to Render via `render.yaml`
- Frontend: Push to `main` → auto-deploys to Vercel

---

## ❗ Do Not
- Add analytics, telemetry, or crash reporting
- Implement user accounts or identity systems
- Store message history or metadata
- Weaken CSP, HSTS, or encryption parameters
