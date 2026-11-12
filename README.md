# PayVoice: Secure Multilingual Financial Agent
### *PayPal AI Hackathon 2026*

PayVoice is a voice-driven, security-first financial management agent designed specifically for **Indian MSME exporters and freelancers** billing international buyers in **USD and EUR** via PayPal.

Because PayPal India operates strictly under RBI Online Payment Gateway Service Provider (OPGSP) guidelines (supporting cross-border merchant export invoicing rather than domestic INR transfers), PayVoice provides seamless international invoicing, transaction search, merchant insights, and tamper-evident encrypted PDF accounting statements.

---

## 🛡️ Core Security Architecture: The Golden Rule

> **"The LLM only parses intent and explains insights. Deterministic Node.js code validates financial policies, and WebAuthn passkeys authorize cryptographic execution."**

1. **Opaque PII Tokenization Vault (`server/services/vault.js`)**: Real buyer names and email addresses are mapped to opaque tokens (e.g. `BUYER_RAHUL_01`) and stored encrypted at rest with **AES-256-GCM** using unique 12-byte initialization vectors and authentication tags. LLM prompts never see raw PII.
2. **Prompt-Injection Firewall (`server/services/guardrail.js`)**: All voice transcripts, memos, and item names are inspected for adversarial injection attacks ("ignore previous rules", role manipulation, unauthorized raw emails) and blocked before execution.
3. **Deterministic Money Guide Engine (`server/services/moneyGuide.js`)**: Pure Node.js enforcement of the \$2,500 USD export value cap, buyer allowlist compliance, currency verification (USD/EUR only; domestic INR is rejected), and duplicate invoice idempotency (15-min rolling window).
4. **Step-Up WebAuthn Passkey Verification (`server/routes/auth.js`)**: Cryptographically binds a single-use FIDO2/WebAuthn challenge to `SHA-256(canonical_json(staged_payload))` with a 2-minute TTL. No invoice can be dispatched without hardware biometric authorization.
5. **Tamper-Evident Hash-Chained Audit Ledger (`server/services/auditLedger.js`)**: Every state transition is appended to a Merkle-style sequential SHA-256 chain:
   $$\text{RowHash}_n = \text{SHA-256}(\text{RowHash}_{n-1} + \text{TranscriptHash} + \text{PayloadHash} + \text{AssertionId} + \text{Status} + \text{Timestamp})$$
6. **Encrypted PDF Accounting Statements (`server/services/pdfGenerator.js`)**: Generates password-protected accounting statements formatted with itemized export transactions, deterministic fee breakdowns, and the latest cryptographic audit chain root.

---

## 🚀 The 6-Step Core Workflow

1. **Multilingual Voice Capture**: Spoken commands in **Marathi**, **Hindi**, or **English** (e.g., *"Rahul la 200 dollars cha software project invoice pathav"*).
2. **Structured AI Intent Extraction**: Intent mapped to strict JSON (`action: create_invoice`, `buyer_token: BUYER_RAHUL_01`, `item: Cloud API Development`, `amount: 200.00`, `currency: USD`).
3. **Deterministic Money Guide Validation**: Validates allowlist, checks \$2,500 limit, confirms currency, and checks duplicate idempotency.
4. **Visual & Audible Read-Back**: Staged preview card rendered on screen and spoken back via browser SpeechSynthesis in the user's selected language.
5. **Step-Up WebAuthn Passkey Verification**: Hardware biometric prompt generates assertion signature matching the payload hash challenge.
6. **PayPal Sandbox Invoicing Lifecycle**: `create_invoice` creates `DRAFT`, `send_invoice` transitions to `SENT`, and Webhook endpoint listens for `INVOICING.INVOICE.PAID`.

---

## 📂 Project Structure

```text
Paypal/
├── .env                         # Sandbox credentials & encryption secrets (git-ignored)
├── .env.example                 # Template for environment configuration
├── .gitignore                   # Credential & secret protection
├── package.json                 # Project dependencies & ESM configuration
├── README.md                    # Project documentation
├── server.js                    # Unified Express application entry point
├── server/
│   ├── config/
│   │   └── paypal.js            # @paypal/agent-toolkit/ai-sdk initialization
│   ├── routes/
│   │   ├── auth.js              # WebAuthn challenge binder & verification
│   │   ├── invoices.js          # POST /api/invoices/stage & POST /api/invoices/execute
│   │   ├── transactions.js      # GET /api/transactions & GET /api/insights
│   │   ├── statements.js        # POST /api/statements/pdf (AES-256 encrypted export)
│   │   └── webhooks.js          # POST /api/webhooks/paypal (INVOICING.INVOICE.PAID)
│   └── services/
│       ├── vault.js             # AES-256-GCM Opaque PII Tokenization Vault
│       ├── guardrail.js         # Prompt-Injection & Schema Firewall
│       ├── moneyGuide.js        # Deterministic financial policy checks
│       ├── auditLedger.js       # SHA-256 hash-chained immutable audit ledger
│       └── pdfGenerator.js      # Encrypted PDF statement export with pdfkit
└── client/
    ├── index.html               # PayVoice Dashboard & Control Panel
    ├── style.css                # Responsive UI styling
    └── app.js                   # Client frontend controller
```

---

## 🛠️ API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/invoices/stage` | Runs Money Guide checks, stages invoice, returns preview card and WebAuthn challenge |
| `POST` | `/api/invoices/execute` | Verifies WebAuthn assertion signature, dispatches PayPal invoice (`DRAFT` $\to$ `SENT`), updates audit ledger |
| `POST` | `/api/statements/pdf` | Generates password-encrypted PDF statement for export transactions |
| `GET` | `/api/transactions` | Lists recent cross-border export transactions |
| `GET` | `/api/transactions/insights` | Retrieves merchant export performance analytics |
| `POST` | `/api/webhooks/paypal` | Ingests PayPal webhook notifications (e.g. `INVOICING.INVOICE.PAID`) |
| `GET` | `/api/audit-ledger` | Fetches the full cryptographic audit ledger |
| `GET` | `/api/audit-ledger/verify` | Validates hash integrity of the entire chain from Genesis |
| `GET` | `/api/vault/buyers` | Lists allowlisted buyers with masked PII |
| `POST` | `/api/vault/buyers` | Enrolls a new buyer in the encrypted vault |

---

## 🚦 Quick Start

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Configure `.env`**:
   ```ini
   PAYPAL_CLIENT_ID=your_sandbox_client_id
   PAYPAL_CLIENT_SECRET=your_sandbox_client_secret
   VAULT_SECRET=your_vault_encryption_secret_2026
   PORT=8888
   PAYPAL_API_BASE=https://api-m.sandbox.paypal.com
   ```

3. **Start the Server**:
   ```bash
   npm start
   ```
   Open **http://localhost:8888** in your browser.
