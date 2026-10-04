// Minimal IMAP4rev1/rev2 client, purpose-built for the cocx junk filter.
//
// WHY IMAP AND NOT mox's OWN APIs
//   mox exposes three programmatic surfaces and none of them alone covers "read the
//   mailbox":
//     * webapi (/webapi/v0/) — Basic-auth JSON, but its Methods interface has NO list
//       or search method. It can Send, and Get/Delete/Move/Flag a message BY MsgID,
//       with no way to discover a MsgID. Verified against mox
//       v0.0.16-0.20260720222435 (webapi/webapi.go `Methods`).
//     * webmail (/webmail/api/) — the SPA's sherpa RPC. Message listing happens over
//       its SSE event stream, not a request/response call, and its ids are internal
//       DB ids.
//     * IMAP — the protocol actually designed for this question.
//   So IMAP owns list/read/flags/move. Message identity is therefore (mailbox, UID,
//   UIDVALIDITY), which is self-consistent — deliberately NOT mox's internal MsgID,
//   which is a different number space and would silently mismatch.
//
// CONNECTION MODEL
//   One connection per request: connect, LOGIN, work, LOGOUT. That costs a TLS
//   handshake (~100ms) per call, which is the right trade for a periodic sweep — no
//   pool to leak, no session to go stale, no cross-request state to reason about.
//
// LITERALS ARE WHY THIS ISN'T A LINE PARSER
//   IMAP responses embed {N}-prefixed byte literals that contain arbitrary bytes,
//   CRLF included. Anything that splits the stream on CRLF corrupts every message
//   body it ever reads. The reader below assembles a LOGICAL line: text segments
//   plus literal Buffers, with the literal lengths honoured exactly.
//
// THE READER IS A CHUNK QUEUE, NOT A GROWING BUFFER — and that is a security property.
//   The obvious `this.buf = Buffer.concat([this.buf, chunk])` on every TCP chunk is
//   O(n²) in the message size. Message bodies here are ATTACKER-SIZED: anyone on the
//   internet can email the account, and mox's default SMTPMaxMessageSize is 100 MB. Measured cost of the concat-per-chunk form, 64 KB chunks:
//       5 MB -> 136 ms      25 MB -> 3.3 s      100 MB -> 51.6 s
//   That is a synchronous event-loop stall triggered by nothing more than a large
//   message arriving — a sweep that times out on it never finishes, so the filter stops
//   filtering for everyone. The queue below is O(n)
//   (100 MB -> 70 ms, ~740x faster) because a literal is consumed BY COUNT and never
//   scanned, and bytes are copied exactly once.
//   Two hard caps back it up: MAX_LINE_BYTES (a line with no CRLF cannot grow forever)
//   and MAX_LITERAL_BYTES (a declared literal larger than this fails the connection
//   rather than being buffered). The per-message policy cap is separate: the filter's
//   fetchRaw maxBytes, checked against RFC822.SIZE *before* any body is transferred.

import tls from 'tls';

const DEFAULT_TIMEOUT_MS = 20_000;
// Protocol-level backstops. Real IMAP protocol lines are short; a literal above the
// hard cap is refused outright so no single message can dominate process memory.
const MAX_LINE_BYTES = 1024 * 1024;
const MAX_LITERAL_BYTES = Number(process.env.IMAP_MAX_LITERAL_BYTES || 32 * 1024 * 1024);

export class ImapError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'ImapError';
    this.code = code || 'imap_error';
  }
}

// IMAP quoted-string. Backslash and double-quote must be escaped, or a value
// containing either breaks the command in a way that reads like bad credentials.
export function imapQuote(s) {
  return '"' + String(s).replace(/([\\"])/g, '\\$1') + '"';
}

// Reject anything that could break out of a quoted string into a new command.
// imapQuote escapes \ and " but CANNOT neutralise a CR or LF — those terminate the
// command line itself, so a mailbox name of `Inbox"\r\nx1 DELETE "Sent` would run a
// second command. Control characters are not legal in mailbox names anyway.
export function assertSafeAstring(value, what = 'value') {
  const s = String(value ?? '');
  if (!s.length) throw new ImapError(`${what} is required`, 'bad_request');
  if (s.length > 255) throw new ImapError(`${what} too long`, 'bad_request');
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1F\x7F]/.test(s)) throw new ImapError(`${what} contains control characters`, 'bad_request');
  return s;
}

export function assertUid(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > 4294967295) {
    throw new ImapError('invalid uid', 'bad_request');
  }
  return n;
}

// ---------------------------------------------------------------- tokenizer

// A logical line arrives as an ordered list of pieces: {text} for protocol text and
// {literal} for a {N}-counted byte run. Tokens come out as:
//   string  — atom or quoted string
//   Buffer  — literal (kept as bytes; a message body must not be lossily decoded here)
//   null    — NIL
//   Array   — parenthesised list
function tokenizePieces(pieces) {
  const root = [];
  const stack = [root];
  const push = (v) => stack[stack.length - 1].push(v);

  for (let pi = 0; pi < pieces.length; pi++) {
    const piece = pieces[pi];
    if (piece.literal !== undefined) { push(piece.literal); continue; }

    // Strip the trailing {N} marker when a literal follows: the assembler already
    // consumed those bytes, and leaving the marker in would tokenize it as an ATOM.
    // That shifts every subsequent name/value pair by one — so BODY[] resolves to the
    // string "{5296}" and a 5 KB message reads back as 6 bytes.
    let t = piece.text;
    if (pieces[pi + 1]?.literal !== undefined) t = t.replace(/\{\d+\+?\}$/, '');
    let i = 0;
    while (i < t.length) {
      const c = t[i];
      if (c === ' ' || c === '\t') { i++; continue; }
      if (c === '(') { const l = []; push(l); stack.push(l); i++; continue; }
      if (c === ')') { if (stack.length > 1) stack.pop(); i++; continue; }
      if (c === '"') {
        let out = '';
        i++;
        while (i < t.length && t[i] !== '"') {
          if (t[i] === '\\' && i + 1 < t.length) { out += t[i + 1]; i += 2; continue; }
          out += t[i]; i++;
        }
        i++; // closing quote
        push(out);
        continue;
      }
      // Atom. '[' and ']' stay inside atoms so BODY[] / BODY[HEADER] arrive whole,
      // and so do response codes like [UIDVALIDITY 123] (read by regex, not here).
      let j = i;
      while (j < t.length && t[j] !== ' ' && t[j] !== '(' && t[j] !== ')') j++;
      const atom = t.slice(i, j);
      push(atom.toUpperCase() === 'NIL' ? null : atom);
      i = j;
    }
  }
  return root;
}

// ---------------------------------------------------------------- connection

class ImapConnection {
  constructor({ host, port, user, pass, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    this.host = host;
    this.port = port;
    this.user = user;
    this.pass = pass;
    this.timeoutMs = timeoutMs;
    this.sock = null;
    this.queue = [];          // unparsed TCP chunks, never concatenated while growing
    this.queueLen = 0;
    this.partial = [];        // pieces of the logical line currently being assembled
    this.awaitLiteral = null; // bytes still owed to an announced {N} literal
    this.pendingLines = [];
    this.waiter = null;      // resolve fn awaiting the next logical line
    this.fatal = null;
    this.tagSeq = 0;
    this.closed = false;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const sock = tls.connect({ host: this.host, port: this.port, servername: this.host }, () => {});
      this.sock = sock;
      sock.setTimeout(this.timeoutMs, () => this._fail(new ImapError('imap timeout', 'timeout')));
      sock.on('error', (e) => this._fail(new ImapError(`imap socket: ${e.message}`, 'network')));
      sock.on('close', () => { if (!this.closed) this._fail(new ImapError('imap connection closed', 'network')); });
      sock.on('data', (chunk) => this._onData(chunk));

      // The greeting is the first logical line; anything sent before it is a protocol
      // error on mox ("leftover data").
      this._nextLine()
        .then((line) => {
          const text = line.pieces.map((p) => (p.literal !== undefined ? '' : p.text)).join('');
          if (!/^\*\s+(OK|PREAUTH)/i.test(text)) {
            return reject(new ImapError(`imap greeting refused: ${text.slice(0, 120)}`, 'greeting'));
          }
          resolve();
        })
        .catch(reject);
    });
  }

  _fail(err) {
    this.fatal = err;
    const w = this.waiter;
    this.waiter = null;
    if (w) w.reject(err);
    try { this.sock?.destroy(); } catch { /* already gone */ }
  }

  _onData(chunk) {
    if (!chunk.length) return;
    this.queue.push(chunk);
    this.queueLen += chunk.length;
    try { this._parse(); } catch (e) { return this._fail(e); }
    this._deliver();
  }

  // Consume EXACTLY n bytes from the queue, copying each byte once. Returns null when
  // the queue is short — this is the path a message body takes, and it never scans.
  _takeBytes(n) {
    if (this.queueLen < n) return null;
    const out = Buffer.allocUnsafe(n);
    let off = 0;
    while (off < n) {
      const c = this.queue[0];
      const need = n - off;
      if (c.length <= need) { c.copy(out, off); off += c.length; this.queue.shift(); }
      else { c.copy(out, off, 0, need); this.queue[0] = c.subarray(need); off = n; }
    }
    this.queueLen -= n;
    return out;
  }

  // One CRLF-terminated protocol line, searched across chunk boundaries (a CR ending
  // one chunk and an LF starting the next is a real case, not a hypothetical).
  _takeTextLine() {
    let idx = -1;
    let seen = 0;
    let prevEndsWithCR = false;
    for (const c of this.queue) {
      if (prevEndsWithCR && c[0] === 0x0A) { idx = seen - 1; break; }
      const at = c.indexOf('\r\n', 0, 'latin1');
      if (at >= 0) { idx = seen + at; break; }
      prevEndsWithCR = c[c.length - 1] === 0x0D;
      seen += c.length;
    }
    if (idx < 0) {
      if (this.queueLen > MAX_LINE_BYTES) {
        throw new ImapError('imap protocol line exceeded the size cap', 'protocol');
      }
      return null;
    }
    const line = this._takeBytes(idx);
    this._takeBytes(2); // the CRLF itself
    return line.toString('latin1');
  }

  // Assemble complete logical lines out of the byte stream, honouring {N} literals.
  // State lives on `this` so a logical line can span any number of TCP reads.
  _parse() {
    for (;;) {
      if (this.awaitLiteral !== null) {
        const lit = this._takeBytes(this.awaitLiteral);
        if (!lit) return;                    // literal still arriving
        this.partial.push({ literal: lit });
        this.awaitLiteral = null;
        continue;
      }
      const text = this._takeTextLine();
      if (text === null) return;             // line still arriving
      this.partial.push({ text });
      // LITERAL+ writes {N+}; both forms carry the same count.
      const m = /\{(\d+)\+?\}$/.exec(text);
      if (m) {
        const n = Number(m[1]);
        if (!Number.isSafeInteger(n) || n > MAX_LITERAL_BYTES) {
          throw new ImapError(`imap literal of ${n} bytes exceeds the ${MAX_LITERAL_BYTES}-byte cap`, 'too_large');
        }
        this.awaitLiteral = n;
        continue;
      }
      this.pendingLines.push({ pieces: this.partial });
      this.partial = [];
    }
  }

  _deliver() {
    while (this.pendingLines.length && this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      w.resolve(this.pendingLines.shift());
    }
  }

  _nextLine() {
    if (this.fatal) return Promise.reject(this.fatal);
    if (this.pendingLines.length) return Promise.resolve(this.pendingLines.shift());
    return new Promise((resolve, reject) => { this.waiter = { resolve, reject }; });
  }

  // Send one command and collect every untagged response up to its tagged completion.
  async exec(command, { redact = false } = {}) {
    if (this.fatal) throw this.fatal;
    const tag = `c${++this.tagSeq}`;
    this.sock.write(`${tag} ${command}\r\n`);

    const untagged = [];
    for (;;) {
      const line = await this._nextLine();
      const flat = line.pieces.map((p) => (p.literal !== undefined ? '' : p.text)).join('');
      if (flat.startsWith(`${tag} `)) {
        const status = flat.slice(tag.length + 1).split(' ')[0].toUpperCase();
        if (status !== 'OK') {
          const detail = redact ? '<redacted>' : flat.slice(tag.length + 1);
          throw new ImapError(`IMAP ${command.split(' ')[0]} failed: ${detail}`, status === 'NO' ? 'imap_no' : 'imap_bad');
        }
        return { untagged, tagged: flat };
      }
      if (flat.startsWith('+ ')) continue;           // continuation request; unused here
      untagged.push({ tokens: tokenizePieces(line.pieces), text: flat });
    }
  }

  async login() {
    // Redacted: a failure message would otherwise echo the command line back.
    await this.exec(`LOGIN ${imapQuote(this.user)} ${imapQuote(this.pass)}`, { redact: true });
  }

  async logout() {
    this.closed = true;
    try { await this.exec('LOGOUT'); } catch { /* server may just close */ }
    try { this.sock?.end(); } catch { /* already gone */ }
    try { this.sock?.destroy(); } catch { /* already gone */ }
  }

  destroy() {
    this.closed = true;
    try { this.sock?.destroy(); } catch { /* already gone */ }
  }
}

// Run one unit of work against a freshly-authenticated connection.
export async function withImap(config, fn) {
  const conn = new ImapConnection(config);
  await conn.connect();
  try {
    await conn.login();
    return await fn(new ImapSession(conn));
  } finally {
    if (conn.closed) conn.destroy(); else await conn.logout();
  }
}

// ---------------------------------------------------------------- operations

const asString = (v) => (v === null || v === undefined ? null : (Buffer.isBuffer(v) ? v.toString('utf8') : String(v)));

// ENVELOPE address item: (name adl mailbox host)
function addrList(list) {
  if (!Array.isArray(list)) return [];
  return list
    .filter(Array.isArray)
    .map((a) => {
      const name = asString(a[0]);
      const mailbox = asString(a[2]);
      const host = asString(a[3]);
      const address = mailbox && host ? `${mailbox}@${host}` : (mailbox || null);
      return { name: name || null, address };
    })
    .filter((a) => a.address);
}

// ENVELOPE = (date subject from sender reply-to to cc bcc in-reply-to message-id)
function parseEnvelope(env) {
  if (!Array.isArray(env)) return {};
  return {
    date: asString(env[0]),
    subject: asString(env[1]),
    from: addrList(env[2]),
    sender: addrList(env[3]),
    replyTo: addrList(env[4]),
    to: addrList(env[5]),
    cc: addrList(env[6]),
    bcc: addrList(env[7]),
    inReplyTo: asString(env[8]),
    messageId: asString(env[9]),
  };
}

/**
 * The TOP-LEVEL content type of a BODYSTRUCTURE, and its parameters. Nothing deeper —
 * a listing badge only needs to know what the message IS.
 *
 * RFC 3501 gives the two forms different shapes, and telling them apart is the whole
 * trick: a multipart body starts with one nested list PER CHILD PART and only then
 * names its subtype, whereas a single part starts with its type string.
 *
 *   single     ("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 1234 20)
 *   multipart  ((child) (child) "ENCRYPTED" ("PROTOCOL" "application/pgp-encrypted" …))
 *
 * Returns null for anything unrecognised. A listing that cannot classify a message
 * shows no badge, which is the correct outcome — never a guess.
 */
function topLevelStructure(bs) {
  if (!Array.isArray(bs) || !bs.length) return null;
  const params = (list) => {
    const out = {};
    if (!Array.isArray(list)) return out;
    for (let i = 0; i + 1 < list.length; i += 2) {
      if (list[i] == null) continue;
      out[String(list[i]).toLowerCase()] = list[i + 1] == null ? '' : String(list[i + 1]);
    }
    return out;
  };
  if (Array.isArray(bs[0])) {
    const at = bs.findIndex((x) => !Array.isArray(x));       // first non-child element
    if (at < 0) return null;
    return {
      contentType: `multipart/${String(bs[at]).toLowerCase()}`,
      params: params(bs[at + 1]),
      childCount: at,
    };
  }
  if (typeof bs[0] !== 'string') return null;
  return {
    contentType: `${String(bs[0]).toLowerCase()}/${String(bs[1] || '').toLowerCase()}`,
    params: params(bs[2]),
    childCount: 0,
  };
}

// FETCH item list -> { UID: …, FLAGS: […], ENVELOPE: […] } keyed by upper-cased name.
function fetchMap(list) {
  const out = {};
  for (let i = 0; i + 1 < list.length; i += 2) {
    const key = String(list[i]).toUpperCase();
    out[key] = list[i + 1];
  }
  return out;
}

export class ImapSession {
  constructor(conn) { this.conn = conn; this.selected = null; }

  async listMailboxes() {
    const { untagged } = await this.conn.exec('LIST "" "*"');
    const boxes = [];
    for (const u of untagged) {
      const t = u.tokens;
      // * LIST (\Archive) "/" Archive
      if (String(t[1]).toUpperCase() !== 'LIST') continue;
      const attrs = Array.isArray(t[2]) ? t[2].map((a) => String(a)) : [];
      const delimiter = asString(t[3]);
      const name = asString(t[4]);
      if (!name) continue;
      boxes.push({ name, delimiter, attributes: attrs, special: attrs.find((a) => a.startsWith('\\') && a !== '\\HasNoChildren' && a !== '\\HasChildren') || null });
    }
    return boxes;
  }

  async status(mailbox, items = ['MESSAGES', 'UNSEEN']) {
    assertSafeAstring(mailbox, 'mailbox');
    const { untagged } = await this.conn.exec(`STATUS ${imapQuote(mailbox)} (${items.join(' ')})`);
    const out = {};
    for (const u of untagged) {
      const t = u.tokens;
      if (String(t[1]).toUpperCase() !== 'STATUS') continue;
      const kv = Array.isArray(t[3]) ? t[3] : [];
      for (let i = 0; i + 1 < kv.length; i += 2) out[String(kv[i]).toUpperCase()] = Number(kv[i + 1]);
    }
    return out;
  }

  // readOnly picks EXAMINE over SELECT so a plain read never clears \Recent or
  // implicitly marks anything seen.
  async select(mailbox, { readOnly = true } = {}) {
    assertSafeAstring(mailbox, 'mailbox');
    const { untagged } = await this.conn.exec(`${readOnly ? 'EXAMINE' : 'SELECT'} ${imapQuote(mailbox)}`);
    const info = { mailbox, exists: 0, uidvalidity: null, uidnext: null };
    for (const u of untagged) {
      let m;
      if ((m = /^\*\s+(\d+)\s+EXISTS/i.exec(u.text))) info.exists = Number(m[1]);
      if ((m = /UIDVALIDITY\s+(\d+)/i.exec(u.text))) info.uidvalidity = Number(m[1]);
      if ((m = /UIDNEXT\s+(\d+)/i.exec(u.text))) info.uidnext = Number(m[1]);
    }
    this.selected = info;
    return info;
  }

  // Criteria are built from structured params by the caller, never concatenated from
  // raw user text — see buildSearchCriteria().
  async uidSearch(criteria = 'ALL') {
    const { untagged } = await this.conn.exec(`UID SEARCH ${criteria}`);
    const uids = [];
    for (const u of untagged) {
      if (!/^\*\s+SEARCH/i.test(u.text)) continue;
      for (let i = 2; i < u.tokens.length; i++) {
        const n = Number(u.tokens[i]);
        if (Number.isInteger(n)) uids.push(n);
      }
    }
    return uids;
  }

  /**
   * Envelopes for a page of UIDs.
   *
   * `structure: true` additionally asks for BODYSTRUCTURE, which is how a listing can
   * say "this one is encrypted" without downloading any message.
   *
   * WHY BODYSTRUCTURE AND NOT A HEADER FETCH. The obvious alternative,
   * `BODY.PEEK[HEADER.FIELDS (CONTENT-TYPE)]`, does not survive this file's tokenizer:
   * the section name contains a parenthesised list, so it tokenizes as the atom
   * `BODY[HEADER.FIELDS`, a list, and a stray `]` — which shifts every name/value pair
   * in fetchMap by one and makes the whole FETCH read back as garbage. BODYSTRUCTURE
   * is a plain parenthesised list, which the tokenizer already handles, and it carries
   * the content-type parameters (protocol=, micalg=) that PGP detection needs.
   */
  async fetchEnvelopes(uids, { structure = false } = {}) {
    if (!uids.length) return [];
    const set = uids.map(assertUid).join(',');
    const { untagged } = await this.conn.exec(
      `UID FETCH ${set} (UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE${structure ? ' BODYSTRUCTURE' : ''})`,
    );
    const out = [];
    for (const u of untagged) {
      // "* <seq> FETCH (...)" — the verb is token 2, after the sequence number. (LIST
      // and STATUS put theirs at token 1; getting this wrong yields a silent empty
      // result rather than an error, which is exactly how it first shipped broken.)
      const t = u.tokens;
      if (String(t[2]).toUpperCase() !== 'FETCH' || !Array.isArray(t[3])) continue;
      const f = fetchMap(t[3]);
      const flags = Array.isArray(f.FLAGS) ? f.FLAGS.map(String) : [];
      out.push({
        uid: Number(f.UID),
        size: Number(f['RFC822.SIZE']) || 0,
        internalDate: asString(f.INTERNALDATE),
        flags,
        seen: flags.some((x) => x.toLowerCase() === '\\seen'),
        answered: flags.some((x) => x.toLowerCase() === '\\answered'),
        flagged: flags.some((x) => x.toLowerCase() === '\\flagged'),
        draft: flags.some((x) => x.toLowerCase() === '\\draft'),
        ...parseEnvelope(f.ENVELOPE),
        ...(structure ? { structure: topLevelStructure(f.BODYSTRUCTURE) } : {}),
      });
    }
    return out;
  }

  // Just RFC822.SIZE — one cheap round trip so a caller can decide whether it wants the
  // body at all. Returns null when the uid does not exist.
  async fetchSize(uid) {
    const u = assertUid(uid);
    const { untagged } = await this.conn.exec(`UID FETCH ${u} (UID RFC822.SIZE)`);
    for (const line of untagged) {
      const t = line.tokens;
      if (String(t[2]).toUpperCase() !== 'FETCH' || !Array.isArray(t[3])) continue;
      const f = fetchMap(t[3]);
      const n = Number(f['RFC822.SIZE']);
      if (Number.isFinite(n)) return n;
    }
    return null;
  }

  // BODY.PEEK[] — PEEK is load-bearing: a bare BODY[] sets \Seen as a side effect, so
  // an agent merely inspecting a mailbox would silently mark it read.
  //
  // maxBytes is checked against RFC822.SIZE FIRST, so an oversized message is refused
  // before a single body byte crosses the wire. Checking after the fetch would mean the
  // process had already paid the whole cost the cap exists to avoid.
  async fetchRaw(uid, { maxBytes = 0 } = {}) {
    const u = assertUid(uid);
    if (maxBytes > 0) {
      const size = await this.fetchSize(u);
      if (size === null) return null;                 // unknown uid — 404, not 413
      if (size > maxBytes) {
        const e = new ImapError(`message is ${size} bytes, over the ${maxBytes}-byte fetch cap`, 'too_large');
        e.size = size;
        e.maxBytes = maxBytes;
        throw e;
      }
    }
    const { untagged } = await this.conn.exec(`UID FETCH ${u} (UID BODY.PEEK[])`);
    for (const line of untagged) {
      const t = line.tokens;
      if (String(t[2]).toUpperCase() !== 'FETCH' || !Array.isArray(t[3])) continue;
      const f = fetchMap(t[3]);
      const body = f['BODY[]'];
      if (Buffer.isBuffer(body)) return body;
      if (typeof body === 'string') return Buffer.from(body, 'binary');
    }
    return null;
  }

  async storeFlags(uid, flags, mode = '+') {
    const u = assertUid(uid);
    // REJECT a malformed flag rather than filtering it out. Silently dropping one flag
    // from a list still returns success, so a caller that asked to remove \Deleted and
    // one typo'd keyword would be told both were applied when only one was.
    const safe = flags.map((f) => {
      const v = assertSafeAstring(f, 'flag');
      if (!/^[\\$]?[A-Za-z0-9_]+$/.test(v)) throw new ImapError(`invalid flag: ${v.slice(0, 40)}`, 'bad_request');
      return v;
    });
    if (!safe.length) throw new ImapError('no valid flags', 'bad_request');
    await this.conn.exec(`UID STORE ${u} ${mode}FLAGS.SILENT (${safe.join(' ')})`);
    return safe;
  }

  async move(uid, destMailbox) {
    const u = assertUid(uid);
    assertSafeAstring(destMailbox, 'mailbox');
    await this.conn.exec(`UID MOVE ${u} ${imapQuote(destMailbox)}`);
  }

  // \Deleted + UID EXPUNGE (UIDPLUS) so only this message is expunged — a bare
  // EXPUNGE would also remove anything else already flagged \Deleted in the mailbox.
  async expunge(uid) {
    const u = assertUid(uid);
    await this.conn.exec(`UID STORE ${u} +FLAGS.SILENT (\\Deleted)`);
    await this.conn.exec(`UID EXPUNGE ${u}`);
  }
}

// ---------------------------------------------------------------- search builder

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// Structured -> IMAP SEARCH. Every free-text value goes through imapQuote after a
// control-character check, so no caller-supplied string can start a new command.
export function buildSearchCriteria({ q, from, to, subject, unseen, flagged, since, before } = {}) {
  const parts = [];
  if (unseen) parts.push('UNSEEN');
  if (flagged) parts.push('FLAGGED');
  if (q) parts.push(`TEXT ${imapQuote(assertSafeAstring(q, 'q'))}`);
  if (from) parts.push(`FROM ${imapQuote(assertSafeAstring(from, 'from'))}`);
  if (to) parts.push(`TO ${imapQuote(assertSafeAstring(to, 'to'))}`);
  if (subject) parts.push(`SUBJECT ${imapQuote(assertSafeAstring(subject, 'subject'))}`);
  for (const [key, value] of [['SINCE', since], ['BEFORE', before]]) {
    if (!value) continue;
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value));
    if (!m) throw new ImapError(`${key.toLowerCase()} must be YYYY-MM-DD`, 'bad_request');
    const mon = MONTHS[Number(m[2]) - 1];
    if (!mon) throw new ImapError(`${key.toLowerCase()} has an invalid month`, 'bad_request');
    parts.push(`${key} ${Number(m[3])}-${mon}-${m[1]}`);
  }
  return parts.length ? parts.join(' ') : 'ALL';
}
