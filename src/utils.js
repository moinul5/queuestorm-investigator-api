/**
 * Request validation and response sanitization utilities.
 * This module is the final safety gate for ALL responses leaving the system.
 */

// ---------------------------------------------------------------------------
// Allowed enum definitions — single source of truth
// ---------------------------------------------------------------------------
export const ALLOWED_ENUMS = {
  evidence_verdict: ['consistent', 'inconsistent', 'insufficient_data'],
  case_type: [
    'wrong_transfer',
    'payment_failed',
    'refund_request',
    'duplicate_payment',
    'merchant_settlement_delay',
    'agent_cash_in_issue',
    'phishing_or_social_engineering',
    'other'
  ],
  severity: ['low', 'medium', 'high', 'critical'],
  department: [
    'customer_support',
    'dispute_resolution',
    'payments_ops',
    'merchant_operations',
    'agent_operations',
    'fraud_risk'
  ]
};

/**
 * Returns `value` if it is in `allowed`, otherwise returns `fallback`.
 * Case-sensitive match required (enums are lowercase by contract).
 *
 * @param {*}      value    - The raw value to validate.
 * @param {Array}  allowed  - The array of allowed string values.
 * @param {string} fallback - The safe default to use when validation fails.
 * @returns {string}
 */
export function forceEnum(value, allowed, fallback) {
  if (typeof value === 'string' && allowed.includes(value)) {
    return value;
  }
  return fallback;
}

// ---------------------------------------------------------------------------
// Official response schema — the 12 allowed output fields (in order)
// ---------------------------------------------------------------------------
const RESPONSE_FIELDS = [
  'ticket_id',
  'relevant_transaction_id',
  'evidence_verdict',
  'case_type',
  'severity',
  'department',
  'agent_summary',
  'recommended_next_action',
  'customer_reply',
  'human_review_required',
  'confidence',
  'reason_codes'
];

// Safety pattern matchers
const SECRETS_REQUEST_REGEX =
  /(?:ask|give|send|share|provide|tell|input|enter|write|verify|confirm)\s+(?:us\s+)?(?:your\s+)?(?:pin|otp|password|cvv|passcode|secret\s*key|card\s*number|card\s*no|full\s*card)/i;

const SECRETS_WARNING_REGEX =
  /do\s+not\s+share|don't\s+share|never\s+share|security\s+reasons|never\s+ask\s+for/i;

const REFUND_CONFIRM_REGEX =
  /(?:refund(?:ed)?\s+you|we\s+will\s+refund|refund\s+is\s+confirmed|money\s+will\s+be\s+refunded|reversal?\s+(?:is|has\s+been)\s+(?:completed|confirmed|done)|will\s+reverse|account\s+(?:is|has\s+been)\s+(?:unblocked|recovered|activated|restored)|money\s+is\s+guaranteed|recovered\s+successfully)/i;

const EXTERNAL_LINK_REGEX =
  /https?:\/\/(?!(?:[a-zA-Z0-9-]+\.)*(?:bkash\.com|sust\.edu))(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b[^\s]*/gi;

const PHONE_REGEX = /\+?(?:880|01)\d{9,11}\b|\+?\d{10,15}\b/g;

// Standard safety reminder appended to all English customer_reply if not present
const PIN_SAFETY_EN =
  'Please do not share your PIN, OTP, or password with anyone, including those claiming to be from us.';

// Bangla safety reminder
const PIN_SAFETY_BN =
  'অনুগ্রহ করে আপনার পিন, ওটিপি বা পাসওয়ার্ড কারো সাথে শেয়ার করবেন না, এমনকি আমাদের পক্ষ থেকে দাবি করা কাউকেও নয়।';

const PIN_PRESENT_REGEX =
  /(?:pin|otp|password|পিন|ওটিপি|পাসওয়ার্ড).*(?:share|don'?t|never|শেয়ার|করবেন না)/i;

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

/**
 * Validates the incoming ticket request schema.
 * Returns { valid: true } or { valid: false, code: HTTP_CODE, error: string }
 */
export function validateRequestSchema(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {
      valid: false,
      code: 400,
      error: 'Request body must be a JSON object'
    };
  }

  // ticket_id — required, non-empty string
  if (body.ticket_id === undefined || body.ticket_id === null) {
    return { valid: false, code: 400, error: 'Missing required field: ticket_id' };
  }
  if (typeof body.ticket_id !== 'string') {
    return { valid: false, code: 422, error: 'ticket_id must be a string' };
  }
  if (body.ticket_id.trim() === '') {
    return { valid: false, code: 422, error: 'ticket_id cannot be empty' };
  }

  // complaint — required, non-empty string
  if (body.complaint === undefined || body.complaint === null) {
    return { valid: false, code: 400, error: 'Missing required field: complaint' };
  }
  if (typeof body.complaint !== 'string') {
    return { valid: false, code: 422, error: 'complaint must be a string' };
  }
  if (body.complaint.trim() === '') {
    return { valid: false, code: 422, error: 'complaint cannot be empty' };
  }

  // transaction_history — optional, but if present must be a valid array
  if (body.transaction_history !== undefined && body.transaction_history !== null) {
    if (!Array.isArray(body.transaction_history)) {
      return { valid: false, code: 422, error: 'transaction_history must be an array' };
    }

    const requiredTxFields = ['transaction_id', 'timestamp', 'type', 'amount', 'counterparty', 'status'];
    for (let i = 0; i < body.transaction_history.length; i++) {
      const tx = body.transaction_history[i];
      if (!tx || typeof tx !== 'object' || Array.isArray(tx)) {
        return { valid: false, code: 422, error: `transaction_history[${i}] must be an object` };
      }
      for (const field of requiredTxFields) {
        if (tx[field] === undefined || tx[field] === null) {
          return {
            valid: false,
            code: 422,
            error: `transaction_history[${i}] is missing required field: ${field}`
          };
        }
      }
      if (typeof tx.amount !== 'number') {
        return { valid: false, code: 422, error: `transaction_history[${i}].amount must be a number` };
      }
    }
  }

  return { valid: true };
}

// ---------------------------------------------------------------------------
// Response sanitization — the mandatory final safety gate
// ---------------------------------------------------------------------------

/**
 * Sanitizes and enforces the official response schema on any raw output object.
 * This function is the final safety gate run against ALL outputs regardless of
 * whether they came from a rules engine, Gemini, or OpenAI.
 *
 * @param {object} response  - The raw response object to sanitize.
 * @param {string} ticketId  - The original ticket_id from the request (authoritative).
 * @param {string} [lang]    - Language from the original request body ('en'|'bn'|'mixed').
 * @returns {object}         - A sanitized response with exactly the 12 allowed fields.
 */
export function sanitizeResponse(response, ticketId, lang = 'en') {
  if (!response || typeof response !== 'object') {
    response = {};
  }

  // ── Step 1: Force enum values and primitive types ─────────────────────────

  const evidence_verdict = forceEnum(
    response.evidence_verdict,
    ALLOWED_ENUMS.evidence_verdict,
    'insufficient_data'
  );

  const case_type = forceEnum(response.case_type, ALLOWED_ENUMS.case_type, 'other');

  const severity = forceEnum(response.severity, ALLOWED_ENUMS.severity, 'medium');

  const department = forceEnum(response.department, ALLOWED_ENUMS.department, 'customer_support');

  const human_review_required =
    typeof response.human_review_required === 'boolean'
      ? response.human_review_required
      : Boolean(response.human_review_required);

  // ticket_id is ALWAYS the authoritative one from the original request
  const ticket_id = String(ticketId || response.ticket_id || '');

  // relevant_transaction_id: must be string or null only
  let relevant_transaction_id = null;
  if (
    response.relevant_transaction_id !== undefined &&
    response.relevant_transaction_id !== null &&
    response.relevant_transaction_id !== ''
  ) {
    relevant_transaction_id = String(response.relevant_transaction_id);
  }

  // confidence: number clamped to [0, 1]
  let confidence = 0.7;
  if (typeof response.confidence === 'number' && !isNaN(response.confidence)) {
    confidence = Math.min(1, Math.max(0, response.confidence));
  }

  // reason_codes: array of short strings
  let reason_codes = [];
  if (Array.isArray(response.reason_codes)) {
    reason_codes = response.reason_codes
      .filter(r => typeof r === 'string' && r.trim().length > 0)
      .map(r => r.trim().slice(0, 64)); // cap each code at 64 chars
  }

  // Text fields — must be non-empty strings
  const agent_summary =
    typeof response.agent_summary === 'string' && response.agent_summary.trim()
      ? response.agent_summary.trim()
      : 'Ticket reviewed. Further investigation required.';

  const recommended_next_action =
    typeof response.recommended_next_action === 'string' && response.recommended_next_action.trim()
      ? response.recommended_next_action.trim()
      : 'Review the customer complaint and transaction details.';

  let customer_reply =
    typeof response.customer_reply === 'string' && response.customer_reply.trim()
      ? response.customer_reply.trim()
      : 'Thank you for contacting support. We are reviewing your query.';

  // ── Step 2: Safety checks on customer_reply ───────────────────────────────

  // 2a. PIN/OTP/password solicitation check
  if (SECRETS_REQUEST_REGEX.test(customer_reply) && !SECRETS_WARNING_REGEX.test(customer_reply)) {
    customer_reply =
      'For your security, we will never ask for your PIN, OTP, password, or full card details. ' +
      'Your case has been escalated to our team for secure review.';
    if (!reason_codes.includes('safety_violation_mitigated')) {
      reason_codes.push('safety_violation_mitigated');
    }
  }

  // 2b. Unauthorized refund/reversal/unblock promise check
  if (REFUND_CONFIRM_REGEX.test(customer_reply)) {
    customer_reply = _substituteRefundLanguage(customer_reply);
    if (!reason_codes.includes('refund_authority_mitigated')) {
      reason_codes.push('refund_authority_mitigated');
    }
  }
  // Also sanitize recommended_next_action for refund promises
  let sanitized_next_action = recommended_next_action;
  if (REFUND_CONFIRM_REGEX.test(sanitized_next_action)) {
    sanitized_next_action = _substituteRefundLanguage(sanitized_next_action);
  }

  // 2c. External URL stripping
  // Reset lastIndex since regex is global/stateful
  EXTERNAL_LINK_REGEX.lastIndex = 0;
  if (EXTERNAL_LINK_REGEX.test(customer_reply)) {
    EXTERNAL_LINK_REGEX.lastIndex = 0;
    customer_reply = customer_reply.replace(EXTERNAL_LINK_REGEX, 'our official support website');
    if (!reason_codes.includes('third_party_redirection_mitigated')) {
      reason_codes.push('third_party_redirection_mitigated');
    }
  }

  // 2d. External phone number stripping (keep official 16247 shortcode)
  PHONE_REGEX.lastIndex = 0;
  if (PHONE_REGEX.test(customer_reply)) {
    PHONE_REGEX.lastIndex = 0;
    customer_reply = customer_reply.replace(PHONE_REGEX, (match) => {
      if (match.includes('16247')) return match;
      return 'our official support hotline';
    });
    if (!reason_codes.includes('third_party_redirection_mitigated')) {
      reason_codes.push('third_party_redirection_mitigated');
    }
  }

  // ── Step 3: Append PIN/OTP safety reminder if not already present ─────────
  const isBangla = lang === 'bn';
  const isMixed = lang === 'mixed';

  if (!PIN_PRESENT_REGEX.test(customer_reply)) {
    if (isBangla) {
      customer_reply = customer_reply.trim() + ' ' + PIN_SAFETY_BN;
    } else {
      // English or mixed — use English reminder
      customer_reply = customer_reply.trim() + ' ' + PIN_SAFETY_EN;
    }
  }

  // ── Step 4: Shape lock — return ONLY the 12 allowed fields in schema order ─
  const shaped = {
    ticket_id,
    relevant_transaction_id,
    evidence_verdict,
    case_type,
    severity,
    department,
    agent_summary,
    recommended_next_action: sanitized_next_action,
    customer_reply,
    human_review_required,
    confidence,
    reason_codes
  };

  // Defensive: verify only RESPONSE_FIELDS keys are present (remove any extras)
  const output = {};
  for (const field of RESPONSE_FIELDS) {
    output[field] = shaped[field];
  }

  return output;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function _substituteRefundLanguage(text) {
  let t = text;
  t = t.replace(/we\s+(?:will\s+)?(?:have\s+)?refund(?:ed)?(?:\s+you)?/gi,
    'any eligible amount will be returned through official channels');
  t = t.replace(/refund\s+is\s+confirmed/gi,
    'any eligible amount will be returned through official channels');
  t = t.replace(/money\s+will\s+be\s+refunded/gi,
    'any eligible amount will be returned through official channels');
  t = t.replace(/will\s+reverse\b/gi,
    'any eligible amount will be returned through official channels');
  t = t.replace(/reversal?\s+(?:is|has\s+been)\s+(?:completed|confirmed|done)/gi,
    'any eligible amount will be returned through official channels');
  t = t.replace(/(?:unblock|recover|activate|restore)\s+your\s+account/gi,
    'process your request through official support channels');
  t = t.replace(/account\s+(?:is|has\s+been)\s+(?:unblocked|recovered|activated|restored)/gi,
    'account status is being reviewed through official support channels');
  t = t.replace(/money\s+is\s+guaranteed/gi,
    'any eligible amount will be returned through official channels after verification');
  t = t.replace(/recovered\s+successfully/gi,
    'processed through official channels');
  // If still contains a forbidden phrase, override entirely
  if (REFUND_CONFIRM_REGEX.test(t)) {
    return 'We have logged your request. Any eligible amount will be returned through official channels after verification.';
  }
  return t;
}
