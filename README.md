# QueueStorm Investigator

An AI-assisted SupportOps copilot for digital finance platforms. Given a customer support ticket and transaction history, it classifies the case, finds the relevant transaction, routes to the correct department, and generates a safe, compliant reply — all without a database and with a full programmatic safety firewall.

Built for the **bKash presents SUST CSE Carnival 2026 · Codex Community Hackathon (Online Preliminary)**.

---

## 🌐 Live Endpoint

```
Base URL: https://your-vercel-url.vercel.app

GET  /health
POST /analyze-ticket
```

> Replace `your-vercel-url` with your actual Vercel deployment URL after deploying.

---

## 📂 Project Structure

```
queuestorm-investigator/
├── .env.example                   # Environment variable template — copy to .env
├── .gitignore
├── vercel.json                    # Vercel serverless routing
├── package.json
├── README.md                      # This file
├── AI_README.md                   # Architecture reference for maintainers / AI editors
├── SUST_Preli_Sample_Cases.json   # 10 public sample test cases with expected output
├── test-runner.js                 # Local test harness (16 tests)
├── samples/
│   └── sample-output.json        # Example output for SAMPLE-01
├── api/
│   └── index.js                  # Express app + Vercel serverless entry point
└── src/
    ├── investigator.js            # Orchestrator: rules baseline → LLM hints → merge → sanitize
    ├── rules.js                   # Rule-based investigation engine (always runs first)
    ├── prompt.js                  # LLM system instruction + injection-safe prompt builder
    └── utils.js                   # Schema validation, enum enforcement, safety sanitizer
```

---

## 🚀 Setup & Local Run

### Prerequisites
- Node.js ≥ 18

### 1 — Install

```bash
npm install
```

### 2 — Configure environment

```bash
cp .env.example .env   # Windows: copy .env.example .env
```

Edit `.env`:

```
PORT=3000
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
```

Both keys are **optional**. The service runs fully offline with the local rule-based engine if no keys are set.

### 3 — Run locally

```bash
npm run dev
# Server starts at http://localhost:3000
```

---

## 🧪 Testing

### Health check

```bash
# Linux / macOS / Git Bash
curl http://localhost:3000/health
# Expected: {"status":"ok"}

# PowerShell
Invoke-WebRequest http://localhost:3000/health | Select-Object -Expand Content
```

### POST a single ticket

```bash
# Linux / macOS / Git Bash
curl -X POST http://localhost:3000/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"TKT-001","complaint":"I sent 5000 taka to the wrong number.","language":"en"}'
```

```powershell
# PowerShell
$body = '{"ticket_id":"TKT-001","complaint":"I sent 5000 taka to the wrong number.","language":"en"}'
Invoke-WebRequest http://localhost:3000/analyze-ticket -Method POST -ContentType "application/json" -Body $body -UseBasicParsing | Select-Object -Expand Content
```

### Full test suite

```bash
node test-runner.js
```

Runs **16 tests** and reports pass / fail for each:

| # | What is tested |
|---|----------------|
| 1 | `GET /health` returns `{"status":"ok"}` |
| 2–11 | All 10 public sample cases from `SUST_Preli_Sample_Cases.json` |
| 12 | Prompt injection — safe blocking, no refund promise, no credential request |
| 13 | Banglish wrong-transfer (`ami vul number e taka pathay`) |
| 14 | Merchant settlement complaint → not classified as `wrong_transfer` |
| 15 | Refund request with empty transaction history → `null` txn + `insufficient_data` |
| 16 | Two payments same amount but **different** merchants → not `duplicate_payment` |

Each test validates: all 12 required fields present, no extra fields, enum validity, `ticket_id` round-trip, `confidence` in `[0,1]`, `reason_codes` is array, no credential solicitation, no unauthorized refund promise.

---

## 🤖 Models & Architecture

### Decision flow

```
POST /analyze-ticket
    │
    ▼
validateRequestSchema()          ← 400 / 422 on bad input
    │
    ▼
rules.js: fallbackInvestigate()  ← ALWAYS runs, never fails
    │  Prompt injection check
    │  Keyword + transaction matching
    │  Evidence verdict, severity, department, human_review
    │  Dynamic text generation (summary, reply, next action)
    │
    ├──► [optional] LLM hints     ← Only when useful (see below)
    │        Gemini 1.5 Flash → GPT-4o-mini fallback
    │        7-second AbortController timeout each
    │        Returns hints only — never the full schema
    │
    ├──► mergeHints()             ← Backend retains all authority
    │        LLM risk_flags appended to reason_codes only
    │        All routing, verdict, reply stay rules-generated
    │
    └──► sanitizeResponse()       ← Final mandatory gate
             Enum enforcement, shape lock (12 fields only)
             PIN/OTP safety, refund-promise prevention
             External URL / phone stripping
    │
    ▼
JSON response (exactly 12 fields)
```

### Tier 1 — Rule-Based Engine (always active, zero cost)

**Location:** `src/rules.js`

Controls all final decisions: `evidence_verdict`, `case_type`, `department`, `severity`, `human_review_required`, `customer_reply`. Handles English, Bangla (Unicode), and Banglish (transliterated). Detects prompt injection attempts before any other classification.

### Tier 2 — Gemini 1.5 Flash (optional runtime helper)

Called when: `language` is `bn` or `mixed`, rule confidence < 0.7, case type is `other`, complaint > 200 characters, or no transaction was matched. Returns **hints only** — the backend rules engine controls all final fields.

### Tier 3 — GPT-4o-mini (optional fallback)

Same hints-only role. Tried if Gemini fails or times out. If both fail, the rules-only result is returned.

### Safety guarantee

> The LLM **never** directly sets any final response field. It provides hints (`detected_case_type`, `mentioned_amount`, `complaint_summary`, `risk_flags`) which the backend may choose to incorporate — only into `reason_codes`. The rules engine and `sanitizeResponse()` have final authority over everything.

---

## 🛡️ Safety Logic

### 1. Prompt injection — detected in rules, before LLM

Complaint text is scanned for instruction-override patterns (`"ignore all rules"`, `"confirm refund"`, `"ask for otp"`, etc.). When detected, the ticket is immediately routed to `phishing_or_social_engineering` / `fraud_risk` / `critical` and `prompt_injection_detected` is added to `reason_codes`. The LLM is never called.

The LLM also receives complaint text inside injection-safe delimiters:

```
<untrusted_complaint_text>
  ...customer text...
</untrusted_complaint_text>
```

### 2. Credential safety

`customer_reply` is scanned for solicitation of PIN, OTP, password, CVV, or card numbers. Any violation is replaced with a secure block message. A PIN/OTP safety reminder is **always** appended to every `customer_reply` (in Bangla if `language: "bn"`).

### 3. Refund / reversal promise prevention

Phrases like `"we will refund you"`, `"refund confirmed"`, `"reversal completed"`, or `"account unblocked"` are detected and replaced with:

> "any eligible amount will be returned through official channels"

### 4. External redirect stripping

Non-official URLs and external phone numbers are replaced with `"our official support website"` / `"our official support hotline"`. The official `16247` shortcode is preserved.

### 5. Schema shape lock

`sanitizeResponse()` always returns **exactly 12 fields** — no more, no less. All enum fields are forced to valid values with safe fallbacks. Extra fields from any source are stripped before the response leaves the system.

---

## 📝 API Contract

### GET /health

**Response `200 OK`:**

```json
{"status": "ok"}
```

### POST /analyze-ticket

**Required request fields:** `ticket_id` (string), `complaint` (string)

**Optional request fields:** `language` (`en` | `bn` | `mixed`), `channel`, `user_type`, `campaign_context`, `transaction_history[]`, `metadata`

**Request example:**

```json
{
  "ticket_id": "TKT-001",
  "complaint": "I sent 5000 taka to a wrong number around 2pm today. Please help.",
  "language": "en",
  "channel": "in_app_chat",
  "user_type": "customer",
  "transaction_history": [
    {
      "transaction_id": "TXN-9101",
      "timestamp": "2026-04-14T14:08:22Z",
      "type": "transfer",
      "amount": 5000,
      "counterparty": "+8801719876543",
      "status": "completed"
    }
  ]
}
```

**Response `200 OK` — exactly 12 fields:**

```json
{
  "ticket_id": "TKT-001",
  "relevant_transaction_id": "TXN-9101",
  "evidence_verdict": "consistent",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending 5000 BDT via TXN-9101 to +8801719876543, which they now believe was the wrong recipient. Recipient is unresponsive.",
  "recommended_next_action": "Verify TXN-9101 details with the customer and initiate the wrong-transfer dispute workflow per policy.",
  "customer_reply": "We have noted your concern about transaction TXN-9101. Our dispute team will review the case and contact you through official support channels. Please do not share your PIN, OTP, or password with anyone, including those claiming to be from us.",
  "human_review_required": true,
  "confidence": 0.9,
  "reason_codes": ["wrong_transfer", "transaction_match"]
}
```

**Allowed enums:**

| Field | Values |
|-------|--------|
| `evidence_verdict` | `consistent` · `inconsistent` · `insufficient_data` |
| `case_type` | `wrong_transfer` · `payment_failed` · `refund_request` · `duplicate_payment` · `merchant_settlement_delay` · `agent_cash_in_issue` · `phishing_or_social_engineering` · `other` |
| `severity` | `low` · `medium` · `high` · `critical` |
| `department` | `customer_support` · `dispute_resolution` · `payments_ops` · `merchant_operations` · `agent_operations` · `fraud_risk` |

**Error responses:**

| Code | Cause |
|------|-------|
| `400` | Malformed JSON or missing required field |
| `422` | Invalid field type or empty required field |
| `500` | Internal error — no stack trace or secret exposed |

---

## ⚡ Deploy to Vercel

### 1 — Install Vercel CLI

```bash
npm install -g vercel
```

### 2 — Deploy

```bash
vercel
```

Or connect the GitHub repository to your Vercel Dashboard for automatic Git deployments.

### 3 — Set environment variables

Go to your Vercel project → **Settings** → **Environment Variables**:

| Variable | Required | Notes |
|----------|----------|-------|
| `GEMINI_API_KEY` | No | Enables Gemini 1.5 Flash for hint extraction |
| `OPENAI_API_KEY` | No | Fallback if Gemini is unavailable |

If neither key is set, the service uses the local rules engine and still returns valid results.

### 4 — Verify

```bash
curl https://your-vercel-url.vercel.app/health
# Expected: {"status":"ok"}

curl -X POST https://your-vercel-url.vercel.app/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"TKT-TEST","complaint":"I sent money to the wrong number."}'
```

---

## 📋 Runbook

| Step | Command |
|------|---------|
| Install | `npm install` |
| Configure | `cp .env.example .env` then add API keys |
| Run locally | `npm run dev` |
| Health check | `curl http://localhost:3000/health` |
| Run test suite | `node test-runner.js` |
| Deploy | `vercel` |
| Set env vars | Vercel Dashboard → Settings → Environment Variables |
| Verify live | `curl https://your-vercel-url.vercel.app/health` |
| View logs | Vercel Dashboard → Functions → Logs |

---

## ⚠️ Known Limitations

- **Banglish edge cases** — Transliterated Bangla with non-standard spelling may not be caught by keyword matching. The LLM hints layer (when enabled) improves coverage for `language: "bn"` or `"mixed"`.
- **LLM availability** — If both Gemini and OpenAI are unavailable or timeout, the service silently falls back to the rules-only result (no error exposed to the caller).
- **Ambiguous evidence** — When multiple transactions match equally and no disambiguating detail (recipient number, transaction ID) is in the complaint, the service returns `insufficient_data` and asks the customer for clarification rather than guessing. This is intentional.
- **No ledger integration** — The service analyses only the transaction history provided in the request body. It does not connect to a live payment system.
- **No language auto-detection** — The `language` field in the request is trusted as-is.

---

## 🔑 Assumptions

- Transaction history in the request body accurately reflects the customer's recent account activity.
- The service is stateless — no session or memory between requests.
- Actual financial actions (refunds, reversals, dispute resolutions) are always performed by human agents after reviewing the case, never by this API.
- No database is used. No customer data is stored.
