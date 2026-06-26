/**
 * Core Ticket Investigator controller.
 *
 * Architecture (rules-first baseline):
 *   1. Run rules.js baseline (always)
 *   2. Optionally call LLM for hints only when useful (timeout: 7 s)
 *   3. Merge LLM hints into rules result (backend retains authority)
 *   4. sanitizeResponse is the final gate (called inside rules.js helpers)
 *   5. Return the shaped, sanitized JSON
 *
 * The LLM NEVER directly determines:
 *   - evidence_verdict, case_type, department, severity
 *   - human_review_required, customer_reply, final schema
 *
 * LLM provides hints only:
 *   - detected_case_type, mentioned_amount, mentioned_counterparty,
 *     mentioned_time, complaint_summary, risk_flags, language_hint
 */

import { SYSTEM_INSTRUCTION, buildUserPrompt } from './prompt.js';
import { fallbackInvestigate, mergeHints } from './rules.js';
import { sanitizeResponse } from './utils.js';

// ---------------------------------------------------------------------------
// Timeout helper
// ---------------------------------------------------------------------------

/**
 * Wraps fetch with an AbortController timeout.
 *
 * @param {string} url         - Request URL.
 * @param {object} options     - fetch options object.
 * @param {number} [ms=7000]   - Timeout in milliseconds.
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options, ms = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// LLM hint extraction — Gemini
// ---------------------------------------------------------------------------

async function callGeminiHints(body, apiKey) {
  const modelName = 'gemini-1.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;

  const userPrompt = buildUserPrompt(body);

  const payload = {
    contents: [
      {
        role: 'user',
        parts: [{ text: userPrompt }]
      }
    ],
    systemInstruction: {
      parts: [{ text: SYSTEM_INSTRUCTION }]
    },
    generationConfig: {
      responseMimeType: 'application/json',
      temperature: 0.1
    }
  };

  const response = await fetchWithTimeout(
    url,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    },
    7000
  );

  if (!response.ok) {
    // Do NOT expose raw error body — log a safe summary only
    console.error(`[Gemini] HTTP ${response.status} — using rules fallback`);
    return null;
  }

  const resJson = await response.json();
  const textContent = resJson.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!textContent) {
    console.error('[Gemini] Empty candidate response — using rules fallback');
    return null;
  }

  return JSON.parse(textContent);
}

// ---------------------------------------------------------------------------
// LLM hint extraction — OpenAI
// ---------------------------------------------------------------------------

async function callOpenAIHints(body, apiKey) {
  const url = 'https://api.openai.com/v1/chat/completions';
  const userPrompt = buildUserPrompt(body);

  const payload = {
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: SYSTEM_INSTRUCTION },
      { role: 'user', content: userPrompt }
    ],
    response_format: { type: 'json_object' },
    temperature: 0.1
  };

  const response = await fetchWithTimeout(
    url,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify(payload)
    },
    7000
  );

  if (!response.ok) {
    console.error(`[OpenAI] HTTP ${response.status} — using rules fallback`);
    return null;
  }

  const resJson = await response.json();
  const textContent = resJson.choices?.[0]?.message?.content;
  if (!textContent) {
    console.error('[OpenAI] Empty message content — using rules fallback');
    return null;
  }

  return JSON.parse(textContent);
}

// ---------------------------------------------------------------------------
// Decide whether LLM hints would be useful
// ---------------------------------------------------------------------------

function shouldUseLLM(body, rulesResult) {
  const lang = body.language || 'en';
  const complaint = body.complaint || '';
  const confidence = rulesResult.confidence || 0;
  const caseType = rulesResult.case_type;

  // Always skip LLM for very clear-cut critical phishing cases — rules are authoritative
  if (caseType === 'phishing_or_social_engineering' && confidence >= 0.9) return false;

  // Use LLM when:
  if (lang === 'bn' || lang === 'mixed') return true;        // Non-English input
  if (confidence < 0.7) return true;                         // Low confidence
  if (caseType === 'other') return true;                     // Uncategorized
  if (complaint.length > 200) return true;                   // Long/complex complaint
  if (!rulesResult.relevant_transaction_id) return true;     // No match found

  return false;
}

// ---------------------------------------------------------------------------
// Validate that LLM-returned object looks like a hints object (not full schema)
// ---------------------------------------------------------------------------

const HINTS_ALLOWED_FIELDS = new Set([
  'detected_case_type',
  'mentioned_amount',
  'mentioned_counterparty',
  'mentioned_time',
  'complaint_summary',
  'risk_flags',
  'language_hint'
]);

function sanitizeHints(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const safe = {};
  for (const key of HINTS_ALLOWED_FIELDS) {
    if (raw[key] !== undefined) {
      safe[key] = raw[key];
    }
  }
  // Validate risk_flags is an array of strings
  if (safe.risk_flags && !Array.isArray(safe.risk_flags)) {
    safe.risk_flags = [];
  }
  // mentioned_amount must be number or null
  if (safe.mentioned_amount !== null && typeof safe.mentioned_amount !== 'number') {
    safe.mentioned_amount = null;
  }
  return safe;
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

/**
 * Investigates a support ticket using rules-first + optional LLM hints.
 *
 * @param {object} body - The validated request body.
 * @returns {Promise<object>} - The sanitized, schema-compliant response.
 */
export async function investigateTicket(body) {
  const ticketId = body.ticket_id;
  const language = body.language || 'en';

  // ── Step 1: Rules baseline (always runs, never fails) ────────────────────
  let rulesResult;
  try {
    rulesResult = fallbackInvestigate(body);
  } catch (err) {
    // Should never happen, but defensive fallback
    console.error('[Rules] Unexpected error in fallbackInvestigate:', err.message);
    rulesResult = sanitizeResponse(
      {
        ticket_id: ticketId,
        evidence_verdict: 'insufficient_data',
        case_type: 'other',
        severity: 'low',
        department: 'customer_support',
        agent_summary: 'Ticket received. Manual review required.',
        recommended_next_action: 'Review customer complaint manually.',
        customer_reply: 'Thank you for contacting us. Our team will review your query.',
        human_review_required: true,
        confidence: 0.3,
        reason_codes: ['rules_engine_error']
      },
      ticketId,
      language
    );
  }

  // ── Step 2: Optionally call LLM for hints ────────────────────────────────
  if (!shouldUseLLM(body, rulesResult)) {
    return rulesResult;
  }

  const geminiKey = process.env.GEMINI_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;

  let llmHints = null;

  // Try Gemini first
  if (geminiKey && geminiKey !== 'your_gemini_api_key_here') {
    try {
      const raw = await callGeminiHints(body, geminiKey);
      llmHints = sanitizeHints(raw);
    } catch (err) {
      // AbortError = timeout, or parse error — safe to ignore
      const reason = err.name === 'AbortError' ? 'timeout' : err.message;
      console.error(`[Gemini] Hints call failed (${reason}) — skipping LLM`);
    }
  }

  // Try OpenAI if Gemini failed or unavailable
  if (!llmHints && openaiKey && openaiKey !== 'your_openai_api_key_here') {
    try {
      const raw = await callOpenAIHints(body, openaiKey);
      llmHints = sanitizeHints(raw);
    } catch (err) {
      const reason = err.name === 'AbortError' ? 'timeout' : err.message;
      console.error(`[OpenAI] Hints call failed (${reason}) — using rules-only result`);
    }
  }

  // ── Step 3: Merge hints (backend retains all authority) ──────────────────
  if (!llmHints) {
    // No LLM output — return rules result as-is
    return rulesResult;
  }

  return mergeHints(rulesResult, llmHints, body);
}
