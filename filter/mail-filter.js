// Body-aware junk filter for the primary mox account (admin@/abuse@/postmaster@).
//
// WHY THIS EXISTS RATHER THAN A mox RULESET
// -----------------------------------------
// mox rulesets (domains.conf -> Destinations -> Rulesets) match on SMTP MAIL FROM, the
// From header, a verified domain, or `HeadersRegexp`. Three consequences, all verified
// against `mox config describe-domains` on a live install rather than assumed:
//
//   1. They cannot see the BODY. The advance-fee mail this was written for has a bland
//      subject ("Urgent Help Needed.") and carries every real signal in the body.
//   2. Their only action is "deliver to mailbox" — there is no reject/drop verdict.
//   3. mox has no milter/sieve hook, so there is no SMTP-time extension point either.
//
// So the drop happens where it can: after delivery, over IMAP, moving matches to Junk.
// That is not a consolation prize. `AutomaticJunkFlags.JunkMailboxRegexp: ^(junk|spam)`
// is already set on the account, so every message this moves TRAINS mox's bayesian
// filter — which does run at SMTP time, and which was sitting at zero junk samples
// (Junk mailbox empty) and therefore classifying nothing. The filter feeds the thing
// that can actually reject, and gets stronger with every message it catches.
//
// WHAT IT DELIBERATELY DOES NOT DO
// --------------------------------
// It never deletes. A move to Junk is recoverable and self-documenting; a delete on a
// heuristic verdict is not, and `abuse@` by definition receives mail that QUOTES spam.
// That is also why `negativePatterns` subtracts on forwarded-report markers.
//
// Scoring is combinational on purpose: total >= threshold AND >= minCategories distinct
// categories. A geopolitical word on its own scores 2 in one category and can never
// reach a verdict — see the crisis_pretext comment in the rules file.

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { withImap } from './imap-client.js';
import { parseMessage } from './mime-parse.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DEFAULT_RULES_PATH = path.join(__dirname, 'rules.json');
const DEFAULT_STATE_PATH = '/var/lib/cocx-mail-filter/state.json';

// A single message's fetch cap. Above this we skip rather than junk: a huge message is
// not evidence of anything, and scoring a truncated body invites a wrong verdict.
const MAX_FETCH_BYTES = 4 * 1024 * 1024;

// ------------------------------------------------------------------ rule loading

let cachedRules = null;
let cachedRulesKey = null;

function compilePatterns(list, where, flags = 'i') {
  const out = [];
  for (const src of list || []) {
    if (typeof src !== 'string' || !src.length) continue;
    if (src.length > 400) throw new Error(`${where}: pattern too long (${src.length} chars)`);
    try {
      out.push({ src, re: new RegExp(src, flags) });
    } catch (e) {
      throw new Error(`${where}: invalid pattern ${JSON.stringify(src)} — ${e.message}`);
    }
  }
  return out;
}

/**
 * Load + compile the rules. MAIL_FILTER_RULES overrides the shipped default so a box can
 * be tuned in place (/etc/cocx/mail-filter-rules.json) without editing the copy that the
 * next `cocx` run reinstalls over the top of it.
 */
export function loadRules({ rulesPath } = {}) {
  const p = rulesPath || process.env.MAIL_FILTER_RULES || DEFAULT_RULES_PATH;
  let stamp = '';
  try {
    const st = fs.statSync(p);
    stamp = `${p}:${st.mtimeMs}:${st.size}`;
  } catch (e) {
    throw new Error(`mail-filter: cannot read rules at ${p} — ${e.message}`);
  }
  if (cachedRules && cachedRulesKey === stamp) return cachedRules;

  const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
  const rules = {
    path: p,
    threshold: Number(raw.threshold ?? 6),
    minCategories: Number(raw.minCategories ?? 2),
    minCategoryScore: Number(raw.minCategoryScore ?? 2),
    quotedCap: Number(raw.quotedCap ?? 2),
    maxBodyBytes: Number(raw.maxBodyBytes ?? 262144),
    allowFromDomains: (raw.allowFromDomains || []).map((d) => String(d).toLowerCase()),
    allowFromAddresses: (raw.allowFromAddresses || []).map((a) => String(a).toLowerCase()),
    freemailDomains: new Set((raw.freemailDomains || []).map((d) => String(d).toLowerCase())),
    structural: raw.structural || {},
    negatives: raw.negatives || {},
    negativePatterns: compilePatterns(raw.negativePatterns, 'negativePatterns'),
    quoteMarkers: compilePatterns(raw.quoteMarkers, 'quoteMarkers', 'im'),
    categories: {},
  };
  for (const [name, cat] of Object.entries(raw.categories || {})) {
    rules.categories[name] = {
      weight: Number(cat.weight ?? 2),
      cap: Number(cat.cap ?? 6),
      // solo: this category maxed out is sufficient evidence on its own, so it satisfies
      // minCategories by itself. Reserved for categories that describe a whole scam
      // shape (advance_fee, seo_outreach) — never for crisis_pretext, whose entire
      // safety property is that it cannot convict without corroboration.
      solo: cat.solo === true,
      patterns: compilePatterns(cat.patterns, `categories.${name}`),
    };
  }
  if (!Object.keys(rules.categories).length) throw new Error(`mail-filter: ${p} defines no categories`);

  cachedRules = rules;
  cachedRulesKey = stamp;
  return rules;
}

// ------------------------------------------------------------------- text prep

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" };

/** HTML -> rough plain text. Only good enough to run regexes over, not to render. */
export function htmlToText(html) {
  if (!html) return '';
  return String(html)
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&(#?\w+);/g, (m, e) => ENTITIES[e.toLowerCase()] ?? (/^#\d+$/.test(e) ? String.fromCharCode(Number(e.slice(1))) : m))
    .replace(/[ \t ]+/g, ' ');
}

const ADDR_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;

/** Pull the bare address out of a "Name <addr>" header value. */
export function addressOf(headerValue) {
  if (!headerValue) return null;
  const angled = /<([^>]+@[^>]+)>/.exec(headerValue);
  const v = angled ? angled[1] : String(headerValue);
  const m = ADDR_RE.exec(v.trim());
  ADDR_RE.lastIndex = 0;
  return m ? m[0].toLowerCase() : null;
}

const domainOf = (addr) => (addr && addr.includes('@') ? addr.split('@').pop().toLowerCase() : null);

// -------------------------------------------------------------------- scoring

/**
 * Score one parsed message. Pure — no IO, no IMAP — so the tests can drive it with
 * fixtures and so `--explain` and the sweep share one code path.
 *
 * @param {object} msg      parseMessage() output
 * @param {object} rules    loadRules() output
 * @param {string[]} localAddresses  our own addresses, lower-cased (for the bcc-blast test)
 * @param {string[]} ownDomains      our own domains, lower-cased: hard-allowed senders,
 *                                   on top of rules.allowFromDomains
 */
export function classify(msg, rules, localAddresses = [], ownDomains = []) {
  const hits = [];
  const catScores = {};
  let score = 0;

  const from = addressOf(msg.from);
  const fromDomain = domainOf(from);

  // Hard allow first — cheap, and it must beat every heuristic below. Our own relays
  // (a website contact form posting as admin@<our domain>) must never be junked. Safe
  // because mox enforces our own DMARC policy at SMTP time: an outsider forging From:
  // <our domain> is rejected before it ever reaches the mailbox.
  const allowed = (why) => ({ junk: false, score: 0, allowed: why, hits: [], categories: [], from, subject: msg.subject || '' });
  if (from && rules.allowFromAddresses.includes(from)) return allowed(`sender ${from}`);
  if (fromDomain && (rules.allowFromDomains.includes(fromDomain) || ownDomains.includes(fromDomain))) {
    return allowed(`domain ${fromDomain}`);
  }

  const add = (category, label, points) => {
    if (!points) return;
    score += points;
    catScores[category] = (catScores[category] || 0) + points;
    hits.push({ category, label, points });
  };

  // ---- structural signals (headers) ----
  const s = rules.structural;
  const to = String(msg.to || '');
  const cc = String(msg.cc || '');
  const recipients = `${to} ${cc}`.toLowerCase();
  const toAddrs = (to.match(ADDR_RE) || []).map((a) => a.toLowerCase());
  const replyTo = addressOf(msg.replyTo);

  if (from && toAddrs.includes(from)) add('structural', 'to-header is the sender (blast)', s.toIsFrom);
  if (/(^|[\s"'<])(recipients?|undisclosed|friend|customer|user|list)\b/i.test(to)) {
    add('structural', 'to-header is a placeholder', s.toPlaceholder);
  }
  if (localAddresses.length && !localAddresses.some((a) => recipients.includes(a))) {
    add('structural', 'we are not in to/cc (bcc blast)', s.bccBlast);
  }
  if (replyTo && from && replyTo !== from) add('structural', `reply-to ${replyTo} != from`, s.replyToMismatch);
  if (fromDomain && rules.freemailDomains.has(fromDomain)) add('structural', `freemail sender (${fromDomain})`, s.freemailSender);

  // ---- body text ----
  const bodyRaw = `${msg.text || ''}\n${htmlToText(msg.html)}`;
  const body = bodyRaw.slice(0, rules.maxBodyBytes);

  // Split the carrier's OWN words from anything it quotes. Quoted text is evidence about
  // the QUOTED message, not about this one — without this split an abuse report that
  // forwards a scam scores identically to the scam, because it contains it. (Measured:
  // the report control scored 19 before the split, comfortably over a threshold of 6.)
  //
  // The quoted region is not discarded, or "-----Original Message-----" pasted at the
  // top would become a one-line evasion. It is scored at a hard GLOBAL cap of
  // rules.quotedCap, credited to whichever category it hit hardest: enough to keep a
  // quote-wrapped scam convictable alongside its header signals, never enough to convict
  // a report whose headers are clean.
  let carrier = body, quoted = '';
  let cut = -1;
  for (const m of rules.quoteMarkers) {
    const hit = m.re.exec(body);
    if (hit && (cut < 0 || hit.index < cut)) cut = hit.index;
  }
  if (cut >= 0) { carrier = body.slice(0, cut); quoted = body.slice(cut); }

  const haystack = `${msg.subject || ''}\n${carrier}`;

  // A different free-mail address buried in the body than the one in From is the
  // signature move of an advance-fee mail (the From account is disposable; replies are
  // steered to the live one). Checked here because it needs both header and body.
  if (from) {
    // carrier, not body: an address inside a quoted scam belongs to the scam.
    const inBody = [...new Set((carrier.match(ADDR_RE) || []).map((a) => a.toLowerCase()))];
    const other = inBody.find((a) => a !== from && a !== replyTo
      && rules.freemailDomains.has(domainOf(a))
      && !localAddresses.includes(a));
    if (other) add('structural', `body steers replies to ${other}`, s.bodyContactAddress);
  }

  // ---- lexicon categories ----
  for (const [name, cat] of Object.entries(rules.categories)) {
    let sub = 0;
    for (const p of cat.patterns) {
      if (sub >= cat.cap) break;
      if (p.re.test(haystack)) {
        sub = Math.min(cat.cap, sub + cat.weight);
        hits.push({ category: name, label: p.src, points: cat.weight });
      }
    }
    if (sub) { score += sub; catScores[name] = sub; }
  }

  // ---- the quoted region, at a global cap (see the split above) ----
  if (quoted) {
    let best = null, bestN = 0;
    for (const [name, cat] of Object.entries(rules.categories)) {
      const n = cat.patterns.reduce((acc, p) => acc + (p.re.test(quoted) ? 1 : 0), 0);
      if (n > bestN) { best = name; bestN = n; }
    }
    if (best) add(best, `quoted text matched ${bestN} ${best} pattern(s), capped`, rules.quotedCap);
  }

  // ---- negatives: this looks like someone REPORTING spam, not sending it ----
  for (const p of rules.negativePatterns) {
    if (p.re.test(haystack)) { add('negative', `forwarded/report marker: ${p.src}`, rules.negatives.forwardedReport); break; }
  }
  if ((msg.attachments || []).some((a) => String(a.contentType).toLowerCase() === 'message/rfc822')) {
    add('negative', 'carries a forwarded message attachment', rules.negatives.rfc822Attachment);
  }

  // A category only counts toward minCategories once it clears minCategoryScore.
  // Without that floor a lone 1-point signal (freemail sender) counted as a whole
  // independent category, which let "gmail sender + names a war" reach a verdict on a
  // real person's email. Two categories has to mean two pieces of evidence.
  const categories = Object.keys(catScores).filter((c) => c !== 'negative' && catScores[c] >= rules.minCategoryScore);
  const soloed = categories.find((c) => rules.categories[c]?.solo && catScores[c] >= rules.categories[c].cap);
  const junk = score >= rules.threshold && (categories.length >= rules.minCategories || Boolean(soloed));

  return { junk, score, categories, soloed: soloed || null, hits, from, subject: msg.subject || '' };
}

// ---------------------------------------------------------------------- state

// UID high-water mark. Without it the sweep would re-judge — and re-junk — a message
// the admin had deliberately rescued back into the Inbox.
export function readState(statePath = process.env.MAIL_FILTER_STATE || DEFAULT_STATE_PATH) {
  try {
    const st = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    return { uidvalidity: Number(st.uidvalidity) || null, lastUid: Number(st.lastUid) || 0 };
  } catch {
    return { uidvalidity: null, lastUid: 0 };
  }
}

export function writeState(state, statePath = process.env.MAIL_FILTER_STATE || DEFAULT_STATE_PATH) {
  fs.mkdirSync(path.dirname(statePath), { recursive: true });
  const tmp = `${statePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ ...state, updatedAt: new Date().toISOString() }, null, 2));
  fs.renameSync(tmp, statePath);
}

// ---------------------------------------------------------------------- sweep

function imapConfig() {
  const user = process.env.MOX_ACCOUNT;
  const pass = process.env.MOX_ACCOUNT_PASSWORD;
  if (!user || !pass) throw new Error('MOX_ACCOUNT / MOX_ACCOUNT_PASSWORD not set (/etc/cocx/mail-filter.env)');
  // The mail hostname, never 127.0.0.1: it doubles as the TLS servername, and mox's
  // certificate is for the hostname, so a loopback address fails verification.
  const host = process.env.MOX_IMAP_HOST;
  if (!host) throw new Error('MOX_IMAP_HOST not set (/etc/cocx/mail-filter.env)');
  return {
    host,
    port: Number(process.env.MOX_IMAP_PORT || 993),
    user,
    pass,
    timeoutMs: 30_000,
  };
}

/** Every address that is "us", for the bcc-blast test. */
function localAddresses() {
  const extra = (process.env.MAIL_FILTER_LOCAL_ADDRESSES || '').split(',').map((a) => a.trim().toLowerCase()).filter(Boolean);
  const acct = (process.env.MOX_ACCOUNT || '').toLowerCase();
  const domain = acct.includes('@') ? acct.split('@').pop() : null;
  const role = domain ? [`abuse@${domain}`, `postmaster@${domain}`] : [];
  return [...new Set([acct, ...role, ...extra].filter(Boolean))];
}

/**
 * Domains whose mail is hard-allowed: the account's own domain unless
 * MAIL_FILTER_ALLOW_OWN_DOMAIN=0, plus MAIL_FILTER_ALLOW_DOMAINS (comma-separated).
 */
function ownDomains() {
  const acct = (process.env.MOX_ACCOUNT || '').toLowerCase();
  const own = process.env.MAIL_FILTER_ALLOW_OWN_DOMAIN !== '0' && acct.includes('@') ? [acct.split('@').pop()] : [];
  const extra = (process.env.MAIL_FILTER_ALLOW_DOMAINS || '').split(',').map((d) => d.trim().toLowerCase()).filter(Boolean);
  return [...new Set([...own, ...extra])];
}

/**
 * Scan the mailbox for messages newer than the high-water mark, score each, and move
 * the junk. Returns a report; with apply=false it changes nothing (including state).
 */
export async function sweep({
  apply = false,
  mailbox = 'Inbox',
  junkMailbox = 'Junk',
  limit = 200,
  rulesPath,
  statePath,
  log = console.log,
} = {}) {
  if (mailbox === junkMailbox) throw new Error('refusing to sweep the junk mailbox into itself');

  const rules = loadRules({ rulesPath });
  const locals = localAddresses();
  const owns = ownDomains();
  const state = readState(statePath);
  const report = { examined: 0, junked: 0, kept: 0, skipped: 0, verdicts: [], apply };

  await withImap(imapConfig(), async (session) => {
    // SELECT (writable) only when we intend to move; EXAMINE otherwise so a dry run
    // cannot even clear \Recent.
    const info = await session.select(mailbox, { readOnly: !apply });

    if (state.uidvalidity && info.uidvalidity !== state.uidvalidity) {
      log(`[mail-filter] uidvalidity changed ${state.uidvalidity} -> ${info.uidvalidity}; resetting high-water mark`);
      state.lastUid = 0;
    }
    state.uidvalidity = info.uidvalidity;

    const from = state.lastUid + 1;
    // `UID n:*` can return the last message even when n is beyond it, so filter again.
    const uids = (await session.uidSearch(`UID ${from}:*`)).filter((u) => u > state.lastUid).sort((a, b) => a - b);
    if (!uids.length) { log(`[mail-filter] ${mailbox}: nothing new above uid ${state.lastUid}`); return; }

    for (const uid of uids.slice(0, limit)) {
      let raw;
      try {
        raw = await session.fetchRaw(uid, { maxBytes: MAX_FETCH_BYTES });
      } catch (e) {
        // Oversized or unfetchable: advance past it, never guess a verdict.
        log(`[mail-filter] uid=${uid} SKIP (${e.message})`);
        report.skipped++;
        state.lastUid = Math.max(state.lastUid, uid);
        continue;
      }
      if (!raw) { report.skipped++; state.lastUid = Math.max(state.lastUid, uid); continue; }

      const msg = parseMessage(raw);
      const v = classify(msg, rules, locals, owns);
      report.examined++;
      report.verdicts.push({ uid, ...v });

      const subj = (v.subject || '').slice(0, 60).replace(/\s+/g, ' ');
      if (v.allowed) {
        log(`[mail-filter] uid=${uid} KEEP  (allowlisted: ${v.allowed}) from=${v.from || '?'} subj="${subj}"`);
        report.kept++;
      } else if (v.junk) {
        const why = v.hits.map((h) => `${h.category}:${h.label}`).slice(0, 6).join(', ');
        log(`[mail-filter] uid=${uid} JUNK  score=${v.score} cats=[${v.categories.join(',')}] from=${v.from || '?'} subj="${subj}" :: ${why}`);
        if (apply) await session.move(uid, junkMailbox);
        report.junked++;
      } else {
        log(`[mail-filter] uid=${uid} KEEP  score=${v.score} cats=[${v.categories.join(',')}] from=${v.from || '?'} subj="${subj}"`);
        report.kept++;
      }
      state.lastUid = Math.max(state.lastUid, uid);
    }
  });

  // Dry runs must not advance the mark, or the real run that follows sees nothing.
  if (apply) writeState(state, statePath);
  log(`[mail-filter] ${apply ? 'applied' : 'DRY RUN'}: examined=${report.examined} junked=${report.junked} kept=${report.kept} skipped=${report.skipped} (rules ${rules.path})`);
  return report;
}

/** Score one message by uid and print the full breakdown. Read-only. */
export async function explain(uid, { mailbox = 'Inbox', rulesPath, log = console.log } = {}) {
  const rules = loadRules({ rulesPath });
  const locals = localAddresses();
  const owns = ownDomains();
  return withImap(imapConfig(), async (session) => {
    await session.select(mailbox, { readOnly: true });
    const raw = await session.fetchRaw(uid, { maxBytes: MAX_FETCH_BYTES });
    if (!raw) { log(`no message with uid ${uid} in ${mailbox}`); return null; }
    const msg = parseMessage(raw);
    const v = classify(msg, rules, locals, owns);
    log(`uid ${uid}  from=${v.from || msg.from}  subject="${msg.subject}"`);
    log(`  to: ${msg.to}`);
    log(`  verdict: ${v.allowed ? `KEEP (allowlisted: ${v.allowed})` : (v.junk ? 'JUNK' : 'KEEP')}  score=${v.score} threshold=${rules.threshold} categories=${v.categories.length}/${rules.minCategories}`);
    for (const h of v.hits) log(`    ${h.points > 0 ? '+' : ''}${h.points}  ${h.category}  ${h.label}`);
    return v;
  });
}

// ------------------------------------------------------------------------ CLI

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  const argv = process.argv.slice(2);
  const has = (f) => argv.includes(f);
  const val = (f, d) => { const i = argv.indexOf(f); return i >= 0 && argv[i + 1] ? argv[i + 1] : d; };

  if (has('--help') || has('-h')) {
    console.log(`mail-filter — score mailbox messages, move junk to Junk (which trains mox's bayes filter)

  node mail-filter.js                    dry run: score everything new, change nothing
  node mail-filter.js --apply            move the junk (what the systemd timer runs)
  node mail-filter.js --explain 12       full score breakdown for one uid, read-only
  node mail-filter.js --rescan --apply   ignore the high-water mark, re-scan the mailbox

options: --mailbox <name> (Inbox)  --junk <name> (Junk)  --limit <n> (200)  --rules <path>  --state <path>
env:     MOX_ACCOUNT, MOX_ACCOUNT_PASSWORD, MOX_IMAP_HOST (/etc/cocx/mail-filter.env)
         MAIL_FILTER_RULES · MAIL_FILTER_STATE · MAIL_FILTER_LOCAL_ADDRESSES
         MAIL_FILTER_ALLOW_OWN_DOMAIN (default 1) · MAIL_FILTER_ALLOW_DOMAINS`);
    process.exit(0);
  }

  const run = async () => {
    if (has('--explain')) {
      await explain(Number(val('--explain', '0')), { mailbox: val('--mailbox', 'Inbox'), rulesPath: val('--rules', undefined) });
      return;
    }
    const statePath = val('--state', undefined);
    if (has('--rescan')) {
      // Deliberately explicit: re-judging already-triaged mail can re-junk a rescued
      // message, so it never happens implicitly.
      const p = statePath || process.env.MAIL_FILTER_STATE || DEFAULT_STATE_PATH;
      try { fs.unlinkSync(p); console.log(`[mail-filter] --rescan: cleared ${p}`); } catch { /* no state yet */ }
    }
    await sweep({
      apply: has('--apply'),
      mailbox: val('--mailbox', 'Inbox'),
      junkMailbox: val('--junk', 'Junk'),
      limit: Number(val('--limit', '200')),
      rulesPath: val('--rules', undefined),
      statePath,
    });
  };

  run().catch((e) => { console.error(`[mail-filter] ${e.stack || e.message}`); process.exit(1); });
}
