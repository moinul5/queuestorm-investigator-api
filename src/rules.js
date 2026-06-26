/**
 * Rule-based baseline investigator for QueueStorm.
 *
 * This module runs FIRST as the primary investigation engine.
 * It produces a structured result from keyword matching and transaction analysis.
 * The LLM is only used afterward as an optional hint-provider to improve
 * complaint understanding and summary quality.
 *
 * The final decisions (case_type, severity, department, verdict,
 * human_review_required, customer_reply) are ALWAYS controlled here,
 * never delegated to the LLM.
 */

import { sanitizeResponse } from './utils.js';

// ---------------------------------------------------------------------------
// Bengali digit normalization
// ---------------------------------------------------------------------------

function normalizeBengaliDigits(text) {
  const bnDigits = {
    '০': '0', '১': '1', '২': '2', '৩': '3', '৪': '4',
    '৫': '5', '৬': '6', '৭': '7', '৮': '8', '৯': '9'
  };
  return text.replace(/[০-৯]/g, char => bnDigits[char]);
}

// ---------------------------------------------------------------------------
// Prompt injection detection
// ---------------------------------------------------------------------------

/**
 * Detects obvious prompt injection attempts in the complaint text.
 * Returns true if suspicious instruction-like patterns are found.
 */
function detectPromptInjection(complaintLower) {
  const injectionPatterns = [
    'ignore all rules',
    'ignore your rules',
    'ignore previous instructions',
    'disregard instructions',
    'forget your instructions',
    'reveal your prompt',
    'show your system prompt',
    'output your instructions',
    'you are now',
    'act as',
    'pretend you are',
    'confirm refund',
    'say we refunded',
    'say refund confirmed',
    'tell the customer refund',
    'ask for otp',
    'ask for pin',
    'ask for password',
    'request otp',
    'request pin',
  ];
  return injectionPatterns.some(p => complaintLower.includes(p));
}

// ---------------------------------------------------------------------------
// Keyword dictionaries — English + Bangla/Banglish
// ---------------------------------------------------------------------------

const KEYWORDS = {
  phishing: [
    'otp', 'pin', 'password', 'cvv', 'passcode', 'verification code', 'secret code',
    'scam', 'fake call', 'fake sms', 'someone asked', 'agent asked', 'bkash support called',
    'share pin', 'share otp', 'bujhiye nilo', 'hacked', 'phishing', 'fraud call',
    'suspicious call', 'account block threat', 'account will be blocked', 'verify account',
    'ওটিপি', 'পাসওয়ার্ড', 'পিন', 'প্রতারণা', 'সন্দেহজনক কল', 'হ্যাক'
  ],

  // IMPORTANT: wrong_transfer keywords must be specific to sending-to-wrong-person.
  // Do NOT use generic "not received" / "didn't get" here — those also match merchant,
  // agent, and payment cases. Only match explicit wrong-recipient intent.
  wrong_transfer: [
    'wrong number', 'wrong recipient', 'wrong transfer', 'wrong person', 'wrong send',
    'bhul number', 'bhul no', 'bhul kore pathay', 'bhul send', 'mistake send',
    'sent to wrong', 'transferred to wrong',
    'vul number', 'vul no', 'vul kore pathay', 'vul send',
    'ami vul', 'wrong e pathay', 'wrong e send',
    'ভুল নাম্বার', 'ভুল নম্বর', 'ভুল করে', 'ভুল সেন্ড', 'ভুল মানুষ', 'ভুল করে পাঠিয়েছি'
  ],

  // "didn't get", "not received", "brother didn't" etc. — only add these when paired
  // with a transfer/send context (checked in detectWrongTransferExtended below)

  agent_cash_in: [
    'agent cash in', 'cash-in', 'cashin', 'agent deposit', 'agent e taka',
    'agent theke deposit', 'agent counter', 'agent tk', 'agent er kach',
    'deposit not reflected', 'balance not updated', 'agent says sent',
    'এজেন্ট', 'ক্যাশ ইন', 'ক্যাশ-ইন'
  ],

  duplicate_payment: [
    'duplicate', 'twice', 'double charge', 'double deduct', 'charged twice',
    'twice charged', 'deducted twice', 'paid twice', 'same payment twice',
    'ekoi payment duibar', 'duibar kete', 'double transaction',
    'দুইবার', 'দুবার', 'টাকাই দুইবার', 'একই পেমেন্ট দুইবার'
  ],

  payment_failed: [
    'failed', 'fail', 'declined', 'unsuccessful', 'deducted but failed',
    'balance deducted payment failed', 'payment failed', 'failed transaction',
    'fail hoyeche', 'tk keteche kintu', 'payment hoyni', 'recharge failed',
    'bill failed', 'transaction failed',
    'ব্যর্থ', 'ফেইল', 'টাকা কেটেছে কিন্তু', 'পেমেন্ট হয়নি'
  ],

  refund: [
    'refund', 'money back', 'return money', 'return my money', 'tk ferot',
    'taka ferot', 'refund request', 'changed my mind', "don't want it",
    'টাকা ফেরত', 'ফেরত', 'ফেরৎ', 'ফেরত দিন'
  ],

  merchant_settlement: [
    'merchant settlement', 'settlement delay', 'merchant payment', 'merchant balance',
    'settlement not received', 'settlement pending', 'settlement cycle', 'settlement',
    'my sales', 'sales not settled', 'not been settled', 'not settled',
    'সেটেলমেন্ট', 'মার্চেন্ট সেটেলমেন্ট'
  ]
};

// ---------------------------------------------------------------------------
// Extended wrong-transfer detection using context
// ---------------------------------------------------------------------------

/**
 * Detects wrong-transfer intent from context patterns that require
 * both a send/transfer verb AND a recipient-didn't-receive signal.
 * This prevents "not received" from being classified as wrong_transfer
 * in merchant/agent/payment contexts.
 *
 * Guard: If the complaint also contains merchant/settlement keywords,
 * we do NOT classify as wrong_transfer — merchant settlement takes priority.
 */
function detectWrongTransferExtended(complaintLower) {
  // Guard: if this looks like a merchant settlement complaint, don't classify as wrong_transfer
  const isMerchantContext =
    complaintLower.includes('settlement') ||
    complaintLower.includes('merchant') ||
    complaintLower.includes('sales') ||
    complaintLower.includes('agent cash') ||
    complaintLower.includes('cashin') ||
    complaintLower.includes('cash-in') ||
    complaintLower.includes('এজেন্ট') ||
    complaintLower.includes('সেটেলমেন্ট');
  if (isMerchantContext) return false;

  // Must have a person-to-person send/transfer signal (not merchant payment)
  const hasSendIntent = /\b(?:sent|send|transfer(?:red)?|pathay(?:echi)?|pathai|diye(?:chi)?|pathiye)\b/.test(complaintLower);
  if (!hasSendIntent) return false;

  // Must have a person recipient (brother, friend, sister, he, she) not-received signal
  const hasPersonRecipientSignal = /(?:brother|friend|sister|bhai|bondhu|সে\s+পায়নি|brother\s+says|friend\s+says|he\s+says|she\s+says)/.test(complaintLower);
  const hasNotReceived = /(?:didn'?t\s+(?:get|receive)|not\s+received|hasn'?t\s+received|he\s+(?:didn'?t|hasn'?t)|she\s+(?:didn'?t|hasn'?t)|পায়নি|টাকা\s+আসেনি)/.test(complaintLower);

  return hasPersonRecipientSignal && hasNotReceived;
}

// ---------------------------------------------------------------------------
// Case keyword matching
// ---------------------------------------------------------------------------

function detectCaseType(complaintLower) {
  // Priority 1: Phishing / social engineering — always wins
  if (KEYWORDS.phishing.some(kw => complaintLower.includes(kw))) {
    return 'phishing_or_social_engineering';
  }

  // Priority 2: Duplicate payment (strong explicit keyword)
  if (KEYWORDS.duplicate_payment.some(kw => complaintLower.includes(kw))) {
    return 'duplicate_payment';
  }

  // Priority 3: Agent cash-in — check before wrong_transfer to prevent misclassification
  // (agent cash-in complaints sometimes say "didn't get" which could wrongly trigger wrong_transfer)
  if (KEYWORDS.agent_cash_in.some(kw => complaintLower.includes(kw))) {
    return 'agent_cash_in_issue';
  }

  // Priority 4: Merchant settlement — check before wrong_transfer
  if (KEYWORDS.merchant_settlement.some(kw => complaintLower.includes(kw))) {
    return 'merchant_settlement_delay';
  }

  // Priority 5: Wrong transfer — explicit keywords OR context-based detection
  if (KEYWORDS.wrong_transfer.some(kw => complaintLower.includes(kw))) {
    return 'wrong_transfer';
  }
  // Extended wrong-transfer: "I sent X to my brother but he didn't get it"
  if (detectWrongTransferExtended(complaintLower)) {
    return 'wrong_transfer';
  }

  // Priority 6: Payment failed
  if (KEYWORDS.payment_failed.some(kw => complaintLower.includes(kw))) {
    return 'payment_failed';
  }

  // Priority 7: Refund
  if (KEYWORDS.refund.some(kw => complaintLower.includes(kw))) {
    return 'refund_request';
  }

  return 'other';
}

// ---------------------------------------------------------------------------
// Department routing
// ---------------------------------------------------------------------------

function routeDepartment(caseType, severity) {
  switch (caseType) {
    case 'phishing_or_social_engineering':
      return 'fraud_risk';
    case 'wrong_transfer':
      return 'dispute_resolution';
    case 'agent_cash_in_issue':
      return 'agent_operations';
    case 'duplicate_payment':
      return 'payments_ops';
    case 'payment_failed':
      return 'payments_ops';
    case 'refund_request':
      // Low-severity / change-of-mind → customer_support
      return (severity === 'low') ? 'customer_support' : 'dispute_resolution';
    case 'merchant_settlement_delay':
      return 'merchant_operations';
    default:
      return 'customer_support';
  }
}

// ---------------------------------------------------------------------------
// Transaction matching
// ---------------------------------------------------------------------------

/**
 * Attempts to find the most relevant transaction from the history.
 *
 * Priority order:
 *  1. Explicit transaction_id mentioned in complaint text
 *  2. Amount match (single unique match)
 *  3. For duplicate_payment: two identical transactions — pick latest
 *  4. Single transaction in history when complaint has contextual clues
 *  5. Ambiguous: multiple equal matches → null (ask for clarification)
 */
function matchTransaction(complaintLower, txHistory, caseType) {
  if (!txHistory || txHistory.length === 0) {
    return { matchedTx: null, relevantTxId: null };
  }

  // 1. Explicit transaction_id mention in complaint
  for (const tx of txHistory) {
    if (tx.transaction_id && complaintLower.includes(tx.transaction_id.toLowerCase())) {
      return { matchedTx: tx, relevantTxId: tx.transaction_id };
    }
  }

  // 2. Amount-based matching
  const numbersInComplaint = complaintLower.match(/\b\d+(?:\.\d+)?\b/g) || [];
  const allParsed = numbersInComplaint.map(n => parseFloat(n)).filter(n => !isNaN(n) && n > 0);

  const amountMatches = [];
  for (const num of allParsed) {
    const hits = txHistory.filter(t => t.amount === num);
    hits.forEach(h => {
      if (!amountMatches.find(m => m.transaction_id === h.transaction_id)) {
        amountMatches.push(h);
      }
    });
  }

  // 3. Duplicate payment — find the latest of the duplicates
  if (caseType === 'duplicate_payment' && amountMatches.length >= 2) {
    const candidates = amountMatches.filter(t => t.status === 'completed');
    if (candidates.length >= 2) {
      const sorted = [...candidates].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      return {
        matchedTx: sorted[sorted.length - 1],
        relevantTxId: sorted[sorted.length - 1].transaction_id
      };
    }
  }

  if (amountMatches.length === 1) {
    return { matchedTx: amountMatches[0], relevantTxId: amountMatches[0].transaction_id };
  }

  if (amountMatches.length > 1) {
    // Ambiguous: multiple transactions match the amount
    return { matchedTx: null, relevantTxId: null, ambiguous: true, candidates: amountMatches };
  }

  // 4. Single transaction in history with complaint context clues
  if (txHistory.length === 1 && (allParsed.length > 0 || caseType !== 'other')) {
    return { matchedTx: txHistory[0], relevantTxId: txHistory[0].transaction_id };
  }

  return { matchedTx: null, relevantTxId: null };
}

/**
 * Checks if two or more transactions in the history appear to be duplicates.
 * Requires SAME amount + SAME counterparty + SAME type + BOTH completed.
 * Returns the suspected duplicate (latest) or null if no pattern found.
 */
function _detectAutoDuplicate(txHistory) {
  const completed = txHistory.filter(t => t.status === 'completed');
  for (let i = 0; i < completed.length; i++) {
    for (let j = i + 1; j < completed.length; j++) {
      const a = completed[i];
      const b = completed[j];
      if (
        a.amount === b.amount &&
        a.counterparty === b.counterparty &&   // MUST be same counterparty
        a.type === b.type
      ) {
        const sorted = [a, b].sort((x, y) => new Date(x.timestamp) - new Date(y.timestamp));
        return sorted[sorted.length - 1];
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Evidence verdict determination
// ---------------------------------------------------------------------------

function determineVerdict(caseType, matchedTx, txHistory, ambiguous) {
  if (ambiguous) return 'insufficient_data';
  if (!matchedTx) return 'insufficient_data';

  switch (caseType) {
    case 'payment_failed': {
      if (matchedTx.status === 'failed' || matchedTx.status === 'pending') return 'consistent';
      if (matchedTx.status === 'completed') return 'inconsistent';
      return 'consistent';
    }

    case 'wrong_transfer': {
      // Inconsistent if customer has MULTIPLE prior transfers to this counterparty
      const priorToSame = txHistory.filter(
        t => t.counterparty === matchedTx.counterparty && t.type === 'transfer'
      );
      if (priorToSame.length > 1) return 'inconsistent';
      return 'consistent';
    }

    case 'duplicate_payment': {
      const dupes = txHistory.filter(
        t =>
          t.amount === matchedTx.amount &&
          t.counterparty === matchedTx.counterparty &&
          t.type === matchedTx.type &&
          t.status === 'completed'
      );
      return dupes.length >= 2 ? 'consistent' : 'insufficient_data';
    }

    case 'agent_cash_in_issue': {
      if (matchedTx.status === 'pending') return 'consistent';
      if (matchedTx.status === 'completed') return 'inconsistent';
      return 'consistent';
    }

    case 'merchant_settlement_delay': {
      if (matchedTx.status === 'pending') return 'consistent';
      return 'consistent';
    }

    default:
      return 'consistent';
  }
}

// ---------------------------------------------------------------------------
// Severity computation
// ---------------------------------------------------------------------------

/**
 * Checks whether the complaint explicitly mentions balance being deducted
 * alongside a payment failure (used for payment_failed severity).
 */
function complainsAboutDeduction(complaintLower) {
  return (
    /(?:balance\s+(?:was\s+)?deducted|money\s+(?:was\s+)?(?:cut|deducted|taken)|tk\s+kete|taka\s+kete|টাকা\s+কেটে|টাকা\s+গেছে)/.test(complaintLower) ||
    complaintLower.includes('deducted but failed') ||
    complaintLower.includes('balance deducted') ||
    complaintLower.includes('money cut') ||
    complaintLower.includes('taka keteche') ||
    complaintLower.includes('tk keteche')
  );
}

function computeSeverity(caseType, evidenceVerdict, matchedTx, complaintLower) {
  switch (caseType) {
    case 'phishing_or_social_engineering':
      return 'critical';

    case 'wrong_transfer':
      // Inconsistent evidence (repeat recipient) → medium
      if (evidenceVerdict === 'inconsistent') return 'medium';
      // Ambiguous / insufficient_data (no match yet) → medium (clarification needed)
      if (evidenceVerdict === 'insufficient_data') return 'medium';
      return 'high';

    case 'duplicate_payment':
      return 'high';

    case 'agent_cash_in_issue':
      return 'high';

    case 'payment_failed':
      // High if the complaint also mentions balance was deducted/cut
      if (complainsAboutDeduction(complaintLower)) return 'high';
      // High if the matched transaction status is 'failed' (confirms system issue)
      if (matchedTx && matchedTx.status === 'failed') return 'high';
      return 'medium';

    case 'refund_request':
      return 'low';

    case 'merchant_settlement_delay':
      return 'medium';

    default:
      return 'low';
  }
}

// ---------------------------------------------------------------------------
// Human review flag
// ---------------------------------------------------------------------------

function requiresHumanReview(caseType, evidenceVerdict, severity, isAmbiguous) {
  // Critical: always human review
  if (severity === 'critical') return true;

  // Inconsistent evidence: always human review (contradictions need investigation)
  if (evidenceVerdict === 'inconsistent') return true;

  // High severity with confirmed evidence
  if (severity === 'high') {
    // payment_failed routed to payments_ops — operational, no human review
    if (caseType === 'payment_failed') return false;
    return true;
  }

  // Ambiguous / insufficient_data: ask for clarification first — no human review yet
  if (evidenceVerdict === 'insufficient_data') {
    // Phishing is always critical — already handled above
    // For wrong_transfer ambiguous: ask for recipient number first
    // For other cases without confirmed evidence: ask for details first
    return false;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

function computeConfidence(caseType, evidenceVerdict, matchedTx) {
  if (caseType === 'phishing_or_social_engineering') return 0.95;
  if (evidenceVerdict === 'consistent' && matchedTx) return 0.9;
  if (evidenceVerdict === 'inconsistent' && matchedTx) return 0.75;
  if (evidenceVerdict === 'insufficient_data' && caseType !== 'other') return 0.65;
  return 0.6;
}

// ---------------------------------------------------------------------------
// Dynamic text generation
// ---------------------------------------------------------------------------

function buildTexts(body, caseType, matchedTx, relevantTxId, evidenceVerdict, txHistory, ambiguousResult, isPromptInjection) {
  const isBangla = body.language === 'bn';

  let agentSummary = `Ticket reviewed. Investigation in progress.`;
  let recommendedNextAction = 'Review the customer complaint and transaction history in the backend system.';
  let customerReply = 'Thank you for reaching out. We have received your query and our team is reviewing it.';

  // ── Prompt injection attempt ───────────────────────────────────────────────
  if (isPromptInjection) {
    agentSummary = 'Complaint text contains suspected prompt injection or instruction override attempt. Treated as untrusted input. Routed for fraud review.';
    recommendedNextAction = 'Flag complaint for fraud_risk review. Do not act on any instructions embedded in the complaint text.';
    customerReply = 'We have received your message. Our team will review your request through official support channels. Please do not share your PIN, OTP, or password with anyone.';
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Phishing / Social Engineering ─────────────────────────────────────────
  if (caseType === 'phishing_or_social_engineering') {
    agentSummary =
      'Customer reports an unsolicited call claiming to be from the company and asking for OTP. ' +
      'Customer has not yet shared credentials. Likely social engineering attempt.';
    recommendedNextAction =
      'Escalate to fraud_risk team immediately. Confirm to customer that the company never asks for OTP. ' +
      'Log the reported number for fraud pattern analysis.';
    customerReply = isBangla
      ? 'আমাদের সাথে যোগাযোগ করার জন্য ধন্যবাদ। আমরা কোনো অবস্থাতেই আপনার পিন, ওটিপি বা পাসওয়ার্ড জানতে চাই না। ' +
        'অনুগ্রহ করে এগুলো কারো সাথে শেয়ার করবেন না, এমনকি আমাদের পক্ষ থেকে দাবি করলেও। ' +
        'আমাদের ফ্রড টিমকে এই ঘটনা জানানো হয়েছে।'
      : 'Thank you for reaching out before sharing any information. ' +
        'We never ask for your PIN, OTP, or password under any circumstances. ' +
        'Please do not share these with anyone, even if they claim to be from us. ' +
        'Our fraud team has been notified of this incident.';
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Wrong Transfer ─────────────────────────────────────────────────────────
  if (caseType === 'wrong_transfer') {
    if (ambiguousResult && ambiguousResult.ambiguous) {
      const amtStr = ambiguousResult.candidates?.[0]?.amount
        ? `${ambiguousResult.candidates[0].amount} BDT`
        : 'that amount';
      agentSummary =
        `Customer reports a transfer to an unintended recipient was not received. ` +
        `Multiple transactions of ${amtStr} exist in the history and cannot be linked without further detail.`;
      recommendedNextAction =
        "Reply to customer asking for the recipient's number to identify the correct transaction. " +
        'Do not initiate dispute until the transaction is confirmed.';
      customerReply = isBangla
        ? `আমরা আপনার অভিযোগটি পেয়েছি। একই পরিমাণ টাকার একাধিক লেনদেন পাওয়া গেছে। ` +
          `সঠিক লেনদেন সনাক্ত করতে অনুগ্রহ করে প্রাপকের নম্বর বা লেনদেন আইডি শেয়ার করুন।`
        : `Thank you for reaching out. We found multiple transactions of that amount in our records. ` +
          `Could you share the recipient's number or transaction ID so we can identify the correct one?`;
    } else if (evidenceVerdict === 'consistent' && matchedTx) {
      const amountStr = matchedTx.amount ? `${matchedTx.amount} BDT` : 'the amount';
      agentSummary =
        `Customer reports sending ${amountStr} via ${relevantTxId} to ${matchedTx.counterparty}, ` +
        `which they now believe was the wrong recipient. Recipient is unresponsive.`;
      recommendedNextAction =
        `Verify ${relevantTxId} details with the customer and initiate the wrong-transfer dispute workflow per policy.`;
      customerReply = isBangla
        ? `আমরা আপনার লেনদেন ${relevantTxId} সংক্রান্ত সমস্যাটি নোট করেছি। ` +
          `আমাদের বিরোধ নিষ্পত্তি দল বিষয়টি যাচাই করে অফিসিয়াল চ্যানেলে আপনাকে জানাবে।`
        : `We have noted your concern about transaction ${relevantTxId}. ` +
          `Our dispute team will review the case and contact you through official support channels.`;
    } else if (evidenceVerdict === 'inconsistent' && matchedTx) {
      const amountStr = matchedTx.amount ? `${matchedTx.amount} BDT` : 'the amount';
      const priorCount = txHistory.filter(
        t => t.counterparty === matchedTx.counterparty && t.type === 'transfer'
      ).length;
      agentSummary =
        `Customer claims ${relevantTxId} (${amountStr} to ${matchedTx.counterparty}) was a wrong transfer, ` +
        `but transaction history shows ${priorCount} prior transfer(s) to the same counterparty, ` +
        `suggesting an established recipient.`;
      recommendedNextAction =
        'Flag for human review. Verify with the customer whether this was genuinely a wrong transfer ' +
        'given the established transaction pattern with this recipient.';
      customerReply =
        `We have received your request regarding transaction ${relevantTxId}. ` +
        `Our dispute team will review the case carefully and contact you through official support channels.`;
    } else {
      agentSummary =
        'Customer reports sending money to a wrong or unintended recipient, but no matching transaction was found in the history.';
      recommendedNextAction =
        'Ask the customer for the transaction ID or recipient number and do not initiate a dispute until the transaction is confirmed.';
      customerReply =
        `We have received your report about the transfer. ` +
        `Please share the transaction ID or the recipient's number so we can locate and investigate the case.`;
    }
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Payment Failed ─────────────────────────────────────────────────────────
  if (caseType === 'payment_failed') {
    if (matchedTx) {
      const amountStr = matchedTx.amount ? `${matchedTx.amount} BDT` : 'the amount';
      if (evidenceVerdict === 'inconsistent') {
        agentSummary =
          `Customer reported a failed payment but transaction ${relevantTxId} status is completed.`;
        recommendedNextAction =
          `Verify ${relevantTxId} ledger logs. Customer claims failure but system shows completed.`;
        customerReply =
          `According to our records, your payment of ${amountStr} (Transaction ID: ${relevantTxId}) ` +
          `appears completed. Please check your balance or verify with the merchant. ` +
          `If you still see an issue, please contact us again.`;
      } else {
        agentSummary =
          `Customer attempted a ${amountStr} payment (${relevantTxId}) which failed, ` +
          `but reports balance was deducted. Requires payments operations investigation.`;
        recommendedNextAction =
          `Investigate ${relevantTxId} ledger status. If balance was deducted on a failed payment, ` +
          `initiate the automatic reversal flow within standard SLA.`;
        customerReply =
          `We have noted that transaction ${relevantTxId} may have caused an unexpected balance deduction. ` +
          `Our payments team will review the case and any eligible amount will be returned through official channels.`;
      }
    } else {
      agentSummary =
        'Customer reports a failed payment, but no matching transaction was found in the provided history.';
      recommendedNextAction =
        'Verify if any recent transaction matching the complaint amount was initiated and investigate ledger status.';
      customerReply =
        'We have recorded your complaint about a failed payment. ' +
        'We are investigating the logs, and any eligible amount will be returned through official channels.';
    }
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Duplicate Payment ─────────────────────────────────────────────────────
  if (caseType === 'duplicate_payment') {
    if (matchedTx && evidenceVerdict === 'consistent') {
      const allDupes = txHistory
        .filter(
          t =>
            t.amount === matchedTx.amount &&
            t.counterparty === matchedTx.counterparty &&
            t.type === matchedTx.type &&
            t.status === 'completed'
        )
        .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      const firstTx = allDupes[0];
      const firstTxId = firstTx ? firstTx.transaction_id : 'the original transaction';
      const amountStr = matchedTx.amount ? `${matchedTx.amount} BDT` : 'the amount';

      let timeDiffNote = '';
      if (allDupes.length >= 2) {
        const diffMs = new Date(allDupes[allDupes.length - 1].timestamp) - new Date(allDupes[0].timestamp);
        const diffSec = Math.round(diffMs / 1000);
        if (diffSec < 120) timeDiffNote = ` ${diffSec} seconds apart`;
        else if (diffSec < 3600) timeDiffNote = ` ${Math.round(diffSec / 60)} minutes apart`;
      }

      agentSummary =
        `Customer reports duplicate payment. Two identical ${amountStr} payments to ` +
        `${matchedTx.counterparty} were completed${timeDiffNote} (${firstTxId} and ${relevantTxId}). ` +
        `The second is likely the duplicate.`;
      recommendedNextAction =
        `Verify the duplicate with payments_ops. If the biller confirms only one payment was received, ` +
        `initiate reversal of ${relevantTxId}.`;
      customerReply =
        `We have noted the possible duplicate payment for transaction ${relevantTxId}. ` +
        `Our payments team will verify with the biller and any eligible amount will be returned through official channels.`;
    } else {
      agentSummary = 'Duplicate payment reported, but evidence does not confirm a clear duplicate.';
      recommendedNextAction = 'Verify invoice and ledger details manually.';
      customerReply =
        'We are looking into the duplicate payment concern. ' +
        'Please share the transaction details through our official support channels to help us process it faster.';
    }
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Agent Cash-In Issue ───────────────────────────────────────────────────
  if (caseType === 'agent_cash_in_issue') {
    if (matchedTx) {
      const amountStr = matchedTx.amount ? `${matchedTx.amount} BDT` : 'the amount';
      agentSummary =
        `Customer reports ${amountStr} cash-in via ${matchedTx.counterparty} (${relevantTxId}) ` +
        `not reflected in balance. Transaction status is ${matchedTx.status}. ` +
        `Agent claims funds were sent.`;
      recommendedNextAction =
        `Investigate ${relevantTxId} pending status with agent operations. ` +
        `Confirm settlement state and resolve within the standard cash-in SLA.`;
      customerReply = isBangla
        ? `আপনার লেনদেন ${relevantTxId} এর বিষয়ে আমরা অবগত হয়েছি। ` +
          `আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে।`
        : `We have received your report regarding agent cash-in (${relevantTxId}). ` +
          `We are investigating with the respective agent point, and any eligible amount will be returned through official channels.`;
    } else {
      agentSummary = 'Agent cash-in issue reported, but no matching transaction was found in history.';
      recommendedNextAction = 'Verify the agent ID and transaction details with the customer.';
      customerReply = isBangla
        ? `আমরা আপনার ক্যাশ ইন সংক্রান্ত অভিযোগ পেয়েছি। ` +
          `বিষয়টি দ্রুত সমাধানের জন্য এজেন্টের নাম বা আইডি শেয়ার করুন।`
        : 'We have received your report regarding the agent cash-in issue. ' +
          'Please share the agent ID or receipt details so we can investigate faster.';
    }
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Refund Request ─────────────────────────────────────────────────────────
  if (caseType === 'refund_request') {
    if (matchedTx) {
      const amountStr = matchedTx.amount ? `${matchedTx.amount} BDT` : 'the amount';
      agentSummary =
        `Customer requests refund of ${amountStr} for ${relevantTxId} ` +
        `(payment to ${matchedTx.counterparty}) due to change of mind or product/service issue. Not a system failure.`;
      recommendedNextAction =
        "Inform the customer that refund eligibility depends on the merchant's own policy. " +
        'Provide guidance on contacting the merchant directly for a refund.';
      customerReply =
        "Thank you for reaching out. Refunds for completed payments depend on the merchant's own policy. " +
        'We recommend contacting the merchant directly. ' +
        'If you need help reaching them, please reply and we will guide you.';
    } else {
      agentSummary = 'Refund request submitted, but matching transaction not found in history.';
      recommendedNextAction = 'Verify the transaction proof from the customer before processing.';
      customerReply =
        'We have received your refund request. ' +
        'Any eligible amount will be returned through official channels after verifying the transaction details.';
    }
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Merchant Settlement Delay ──────────────────────────────────────────────
  if (caseType === 'merchant_settlement_delay') {
    if (matchedTx) {
      const amountStr = matchedTx.amount ? `${matchedTx.amount} BDT` : 'the amount';
      agentSummary =
        `Merchant reports ${amountStr} settlement (${relevantTxId}) is delayed beyond the standard next-day window. ` +
        `Settlement status is ${matchedTx.status}.`;
      recommendedNextAction =
        'Route to merchant_operations to verify settlement batch status. ' +
        'If the batch is delayed, communicate a revised ETA to the merchant.';
      customerReply =
        `We have noted your concern about settlement ${relevantTxId}. ` +
        `Our merchant operations team will check the batch status and update you on the expected settlement time through official channels.`;
    } else {
      agentSummary = 'Merchant settlement delay reported, but no matching settlement transaction found.';
      recommendedNextAction = 'Check settlement cycle and transfer logs for the merchant account.';
      customerReply =
        'We are investigating the settlement delay. ' +
        'Our merchant operations team will review the batch status and contact you through official channels.';
    }
    return { agentSummary, recommendedNextAction, customerReply };
  }

  // ── Other / Vague Complaint ────────────────────────────────────────────────
  agentSummary =
    'Customer reports a vague concern about their account without specifying a transaction, amount, or clear issue. ' +
    'Insufficient detail to identify any relevant transaction or case type.';
  recommendedNextAction =
    'Reply to customer asking for specific details: which transaction, what amount, what went wrong, and approximate time.';
  customerReply =
    'Thank you for reaching out. To help you faster, please share the transaction ID, ' +
    'the amount involved, and a short description of what went wrong.';

  return { agentSummary, recommendedNextAction, customerReply };
}

// ---------------------------------------------------------------------------
// Main exported function: rule-based investigation baseline
// ---------------------------------------------------------------------------

/**
 * Runs the full rule-based investigation on the ticket.
 * Returns a sanitized response object following the official schema.
 *
 * @param {object} body - The validated request body.
 * @returns {object}    - Sanitized response object.
 */
export function fallbackInvestigate(body) {
  const ticketId = body.ticket_id;
  const complaint = body.complaint || '';
  const normalizedComplaint = normalizeBengaliDigits(complaint);
  const complaintLower = normalizedComplaint.toLowerCase();
  const txHistory = Array.isArray(body.transaction_history) ? body.transaction_history : [];
  const language = body.language || 'en';

  // ── Step 0: Prompt injection check ───────────────────────────────────────
  const isPromptInjection = detectPromptInjection(complaintLower);

  // ── Step 1: Classify case type ────────────────────────────────────────────
  // If prompt injection detected, route to fraud_risk immediately
  let caseType = isPromptInjection
    ? 'phishing_or_social_engineering'
    : detectCaseType(complaintLower);

  // ── Step 2: Transaction matching ──────────────────────────────────────────
  const matchResult = matchTransaction(complaintLower, txHistory, caseType);
  let { matchedTx, relevantTxId } = matchResult;
  const isAmbiguous = !!matchResult.ambiguous;

  // Auto-detect duplicate payment from transaction history even without keywords.
  // REQUIRES same counterparty — prevents false positives with different merchants.
  if (caseType !== 'phishing_or_social_engineering' && caseType !== 'duplicate_payment') {
    const autoDup = _detectAutoDuplicate(txHistory);
    if (autoDup) {
      // Only upgrade if the complaint is about billing/deduction/payment
      const dupClue =
        complaintLower.includes('deduct') ||
        complaintLower.includes('charge') ||
        complaintLower.includes('paid') ||
        complaintLower.includes('bill') ||
        complaintLower.includes('payment') ||
        complaintLower.includes('twice');
      if (dupClue) {
        caseType = 'duplicate_payment';
        matchedTx = autoDup;
        relevantTxId = autoDup.transaction_id;
      }
    }
  }

  // ── Step 3: Evidence verdict ──────────────────────────────────────────────
  let evidenceVerdict = determineVerdict(caseType, matchedTx, txHistory, isAmbiguous);

  // Phishing → always insufficient_data (no financial tx to match)
  if (caseType === 'phishing_or_social_engineering') {
    evidenceVerdict = 'insufficient_data';
    relevantTxId = null;
    matchedTx = null;
  }

  // Vague/other + no match → insufficient_data
  if (caseType === 'other' && !matchedTx) {
    evidenceVerdict = 'insufficient_data';
  }

  // ── Step 4: Severity ──────────────────────────────────────────────────────
  const severity = computeSeverity(caseType, evidenceVerdict, matchedTx, complaintLower);

  // ── Step 5: Department routing ────────────────────────────────────────────
  const department = routeDepartment(caseType, severity);

  // ── Step 6: Human review flag ─────────────────────────────────────────────
  const humanReviewRequired = requiresHumanReview(caseType, evidenceVerdict, severity, isAmbiguous);

  // ── Step 7: Confidence ────────────────────────────────────────────────────
  const confidence = computeConfidence(caseType, evidenceVerdict, matchedTx);

  // ── Step 8: Reason codes ──────────────────────────────────────────────────
  const reasonCodes = buildReasonCodes(caseType, evidenceVerdict, matchedTx, isAmbiguous, isPromptInjection);

  // ── Step 9: Dynamic text generation ──────────────────────────────────────
  const texts = buildTexts(
    body,
    caseType,
    matchedTx,
    relevantTxId,
    evidenceVerdict,
    txHistory,
    isAmbiguous ? matchResult : null,
    isPromptInjection
  );

  // ── Step 10: Assemble raw response ────────────────────────────────────────
  const rawResponse = {
    ticket_id: ticketId,
    relevant_transaction_id: relevantTxId,
    evidence_verdict: evidenceVerdict,
    case_type: caseType,
    severity,
    department,
    agent_summary: texts.agentSummary,
    recommended_next_action: texts.recommendedNextAction,
    customer_reply: texts.customerReply,
    human_review_required: humanReviewRequired,
    confidence,
    reason_codes: reasonCodes
  };

  // ── Step 11: Pass through safety sanitizer ────────────────────────────────
  return sanitizeResponse(rawResponse, ticketId, language);
}

/**
 * Merges LLM hints into a rules baseline result.
 * The backend rules engine retains authority over ALL final field values.
 * LLM hints may only contribute to: reason_codes (risk_flags).
 * The summary text stays rules-generated to avoid LLM manipulation.
 *
 * @param {object} rulesResult - The output of fallbackInvestigate
 * @param {object} llmHints    - The structured hints from the LLM
 * @param {object} body        - The original request body
 * @returns {object}           - Merged result (still sanitized)
 */
export function mergeHints(rulesResult, llmHints, body) {
  if (!llmHints || typeof llmHints !== 'object') return rulesResult;

  const language = body.language || 'en';

  // Risk flags from LLM can be appended to reason_codes (filtered for safety)
  let reasonCodes = [...rulesResult.reason_codes];
  if (Array.isArray(llmHints.risk_flags)) {
    for (const flag of llmHints.risk_flags) {
      if (typeof flag === 'string' && flag.trim() && !reasonCodes.includes(flag.trim())) {
        // Never include flags that could reference credentials or system internals
        if (!/key|token|secret|api|password|otp|pin|cvv/i.test(flag)) {
          reasonCodes.push(flag.trim().slice(0, 64));
        }
      }
    }
  }

  const merged = {
    ...rulesResult,
    reason_codes: reasonCodes
  };

  // Run through sanitizer again as a final safety gate
  return sanitizeResponse(merged, body.ticket_id, language);
}

// ---------------------------------------------------------------------------
// Reason code builder
// ---------------------------------------------------------------------------

function buildReasonCodes(caseType, evidenceVerdict, matchedTx, isAmbiguous, isPromptInjection) {
  const codes = [];

  if (isPromptInjection) {
    codes.push('prompt_injection_detected');
  }

  codes.push(caseType);

  if (isAmbiguous) {
    codes.push('ambiguous_match');
    codes.push('needs_clarification');
  } else if (matchedTx) {
    codes.push('transaction_match');
  } else {
    codes.push('no_transaction_match');
  }

  if (evidenceVerdict === 'inconsistent') codes.push('evidence_inconsistent');
  if (evidenceVerdict === 'insufficient_data' && !isAmbiguous) codes.push('insufficient_data');

  if (caseType === 'wrong_transfer' && evidenceVerdict === 'inconsistent') {
    codes.push('established_recipient_pattern');
  }
  if (caseType === 'duplicate_payment' && evidenceVerdict === 'consistent') {
    codes.push('biller_verification_required');
  }
  if (caseType === 'phishing_or_social_engineering') {
    codes.push('credential_protection');
    codes.push('critical_escalation');
  }
  if (caseType === 'agent_cash_in_issue' && matchedTx?.status === 'pending') {
    codes.push('pending_transaction');
    codes.push('agent_ops');
  }
  if (caseType === 'merchant_settlement_delay') {
    codes.push('delay');
    if (matchedTx?.status === 'pending') codes.push('pending');
  }
  if (caseType === 'refund_request') {
    codes.push('merchant_policy_dependent');
  }
  if (caseType === 'payment_failed' && matchedTx) {
    codes.push('potential_balance_deduction');
  }
  if (caseType === 'other') {
    codes.push('vague_complaint');
  }

  return codes;
}
