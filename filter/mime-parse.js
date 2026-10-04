// RFC 5322 / MIME parsing for the cocx junk filter.
//
// WHY THIS EXISTS: IMAP hands back a raw message (see imap-client.js for why IMAP owns
// reading). Something has to turn those bytes into { subject, from, text, html,
// attachments } — mox's webapi would do it, but only for a MsgID we have no way to
// discover. This is the small, auditable version of that job.
//
// SECURITY POSTURE — the content here is ATTACKER-AUTHORED. Anyone on the internet can
// send mail to the account. Therefore:
//   * Nothing is executed, resolved or fetched. HTML is returned as a STRING and is
//     never rendered by this code; the filter only runs regexes over it.
//   * Every size is capped and every recursion is depth-limited, so a hostile message
//     cannot turn a read into an OOM or a hang.
//   * Charset decoding is best-effort and never throws — an undecodable part degrades
//     to latin1 rather than failing the whole request.

// SECURITY: the header parser had no cap of any kind while text, part count and depth all did.
// splitHeadersBody returns the WHOLE buffer as header text when it finds no blank-line
// separator, so an emailed part of header-shaped lines produced millions of objects
// synchronously on the event loop — one hostile message stalling every sweep after it.
const MAX_HEADERS = 512;
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_TEXT_BYTES = 512 * 1024;   // per text/html part returned inline
const MAX_PARTS = 200;               // MIME parts walked before we stop
const MAX_DEPTH = 12;                // nesting depth before we stop descending

// ---------------------------------------------------------------- headers

// Unfold (RFC 5322 3.2.2) and split into ordered name/value pairs. Folding is the
// reason a naive split('\n') mangles long Subject/References headers.
export function parseHeaders(headerText) {
  const out = [];
  // SECURITY: bound BOTH the input and the output. The text is attacker-authored (mail from the
  // open internet) and the caller can hand us a whole part body when it contains no blank-line
  // separator, so an uncapped split+push built one object per line — millions of them,
  // synchronously, on a shared event loop.
  const src = headerText.length > MAX_HEADER_BYTES ? headerText.slice(0, MAX_HEADER_BYTES) : headerText;
  const lines = src.split(/\r?\n/);
  let current = null;
  for (const line of lines) {
    if (out.length >= MAX_HEADERS) break;
    if (/^[ \t]/.test(line) && current) { current.value += ' ' + line.trim(); continue; }
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    current = { name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() };
    out.push(current);
  }
  return out;
}

const headerGet = (headers, name) => {
  const lower = name.toLowerCase();
  const hit = headers.find((h) => h.name.toLowerCase() === lower);
  return hit ? hit.value : null;
};

// ---------------------------------------------------------------- charset

function decodeCharset(buf, charset) {
  const label = (charset || 'utf-8').toLowerCase().replace(/["']/g, '');
  try {
    return new TextDecoder(label, { fatal: false }).decode(buf);
  } catch {
    // Unknown label (TextDecoder throws on construction, not on decode). latin1 never
    // fails and never loses bytes, which beats dropping the part entirely.
    try { return new TextDecoder('utf-8', { fatal: false }).decode(buf); } catch { return buf.toString('latin1'); }
  }
}

// ---------------------------------------------------------------- RFC 2047

// =?charset?B|Q?encoded?= in header values (Subject, display names, filenames).
//
// The whitespace rule is the subtle part and RFC 2047 §6.2 is specific about it:
// whitespace BETWEEN TWO ADJACENT encoded-words is ignored (it exists only to let long
// headers fold), but whitespace between an encoded-word and ordinary text is real
// content. Collapsing both — the obvious single-regex version — turns
// "=?UTF-8?B?...?= <jorg@example.com>" into "Jörg Müller<jorg@example.com>", quietly
// corrupting every display name that precedes an address.
export function decodeWords(value) {
  if (!value || value.indexOf('=?') < 0) return value || '';
  // Step 1: drop the separator ONLY where an encoded-word is followed by another.
  const joined = String(value).replace(/\?=[ \t]+(?==\?)/g, '?=');
  // Step 2: decode each word in place, leaving all remaining whitespace untouched.
  return joined.replace(
    /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g,
    (match, charset, enc, text) => {
      try {
        let bytes;
        if (enc.toUpperCase() === 'B') {
          bytes = Buffer.from(text, 'base64');
        } else {
          // Q-encoding: '_' is a space, =XX is a byte.
          bytes = Buffer.from(
            text.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16))),
            'latin1',
          );
        }
        return decodeCharset(bytes, charset);
      } catch {
        return match;
      }
    },
  );
}

// ---------------------------------------------------------------- structured values

// "multipart/mixed; boundary="abc"; charset=utf-8" -> {type, subtype, params}
export function parseContentType(value) {
  const raw = (value || 'text/plain').trim();
  const semi = raw.indexOf(';');
  const full = (semi < 0 ? raw : raw.slice(0, semi)).trim().toLowerCase();
  const [type, subtype = ''] = full.split('/');
  return { type: type || 'text', subtype, full: subtype ? `${type}/${subtype}` : type, params: parseParams(semi < 0 ? '' : raw.slice(semi + 1)) };
}

function parseParams(s) {
  const params = {};
  const re = /([A-Za-z0-9!#$%&'*+.^_`|~-]+)\*?\s*=\s*("([^"]*)"|[^;]*)/g;
  let m;
  while ((m = re.exec(s))) {
    const key = m[1].toLowerCase().replace(/\*$/, '');
    let val = (m[3] !== undefined ? m[3] : m[2]).trim();
    // RFC 2231 extended form: charset'lang'percent-encoded
    const ext = /^([^']*)'([^']*)'(.*)$/.exec(val);
    if (ext) {
      try { val = decodeCharset(Buffer.from(ext[3].replace(/%([0-9A-Fa-f]{2})/g, (_x, h) => String.fromCharCode(parseInt(h, 16))), 'latin1'), ext[1]); } catch { /* keep raw */ }
    }
    params[key] = decodeWords(val);
  }
  return params;
}

// ---------------------------------------------------------------- transfer encodings

function decodeQuotedPrintable(buf) {
  const s = buf.toString('latin1');
  const unfolded = s.replace(/=\r?\n/g, '');
  const out = Buffer.alloc(unfolded.length);
  let n = 0;
  for (let i = 0; i < unfolded.length; i++) {
    if (unfolded[i] === '=' && i + 2 < unfolded.length && /^[0-9A-Fa-f]{2}$/.test(unfolded.substr(i + 1, 2))) {
      out[n++] = parseInt(unfolded.substr(i + 1, 2), 16);
      i += 2;
    } else {
      out[n++] = unfolded.charCodeAt(i) & 0xFF;
    }
  }
  return out.subarray(0, n);
}

function decodeTransfer(buf, encoding) {
  const enc = (encoding || '7bit').trim().toLowerCase();
  if (enc === 'base64') return Buffer.from(buf.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  if (enc === 'quoted-printable') return decodeQuotedPrintable(buf);
  return buf; // 7bit / 8bit / binary
}

// ---------------------------------------------------------------- part splitting

function splitHeadersBody(buf) {
  // Accept both CRLF and bare-LF separators — mail in the wild has both.
  let idx = buf.indexOf('\r\n\r\n');
  let skip = 4;
  const lfIdx = buf.indexOf('\n\n');
  if (idx < 0 || (lfIdx >= 0 && lfIdx < idx)) { idx = lfIdx; skip = 2; }
  // SECURITY: with no separator the WHOLE buffer used to be treated as headers. Cap what may be
  // read as a header block and hand the overflow back as body, so a separator-less part cannot
  // turn its entire payload into header objects.
  if (idx < 0) {
    if (buf.length > MAX_HEADER_BYTES) {
      return { headerText: buf.toString('latin1', 0, MAX_HEADER_BYTES), body: buf.subarray(MAX_HEADER_BYTES) };
    }
    return { headerText: buf.toString('latin1'), body: Buffer.alloc(0) };
  }
  return { headerText: buf.toString('latin1', 0, idx), body: buf.subarray(idx + skip) };
}

// Split a multipart body on its boundary. Returns the child part buffers in order.
function splitMultipart(body, boundary) {
  const delim = `--${boundary}`;
  const text = body.toString('latin1');
  const parts = [];
  let pos = 0;
  let start = -1;
  for (;;) {
    const at = text.indexOf(delim, pos);
    if (at < 0) break;
    const afterIdx = at + delim.length;
    const after = text.substr(afterIdx, 2);
    const isClose = after.startsWith('--');
    // Boundary must sit at the start of a line.
    if (at !== 0 && text[at - 1] !== '\n') { pos = afterIdx; continue; }
    if (start >= 0) {
      let end = at;
      if (end > 0 && text[end - 1] === '\n') end--;
      if (end > 0 && text[end - 1] === '\r') end--;
      parts.push(body.subarray(start, end));
    }
    if (isClose) break;
    const nl = text.indexOf('\n', afterIdx);
    if (nl < 0) break;
    start = nl + 1;
    pos = start;
  }
  return parts;
}

// ---------------------------------------------------------------- tree walk

function walkPart(buf, path, ctx) {
  if (ctx.count >= MAX_PARTS || path.length > MAX_DEPTH) { ctx.truncatedTree = true; return; }
  ctx.count++;

  const { headerText, body } = splitHeadersBody(buf);
  const headers = parseHeaders(headerText);
  const ct = parseContentType(headerGet(headers, 'content-type'));
  const cte = headerGet(headers, 'content-transfer-encoding');
  const cd = headerGet(headers, 'content-disposition') || '';
  const disposition = cd.split(';')[0].trim().toLowerCase() || null;
  const dparams = parseParams(cd.includes(';') ? cd.slice(cd.indexOf(';') + 1) : '');
  const filename = dparams.filename || ct.params.name || null;
  const partPath = path.join('.');

  // The STRUCTURAL tree — every part in document order, container parts included.
  //
  // This exists because `attachments[]` below is a *presentation* list: it holds the
  // leaves that are not the displayable text, and it never mentions the multipart
  // containers at all. That is the right shape for rendering a message and the wrong
  // shape for asking a structural question about one. PGP/MIME (RFC 3156) is exactly
  // such a question — "is the TOP-LEVEL part multipart/encrypted with
  // protocol=application/pgp-encrypted, and is its second child the ciphertext" — and
  // answering it from `attachments[]` degenerates into sniffing filenames and
  // content-types, which is how a signed message gets mistaken for an encrypted one.
  //
  // Deliberately metadata only: no bodies, so this stays O(parts) in memory and cannot
  // become a second copy of the message. Bodies are fetched by path via getPart().
  ctx.parts.push({
    partPath,
    contentType: ct.full,
    // protocol/micalg/boundary drive every RFC 3156 decision; charset/name are what a
    // caller needs to interpret the bytes it then fetches.
    params: ct.params,
    disposition,
    filename: filename ? decodeWords(filename) : null,
    // Present for containers too — a caller walking the tree needs to know a part HAS
    // children without re-splitting it.
    multipart: ct.type === 'multipart' && !!ct.params.boundary,
  });

  if (ct.type === 'multipart' && ct.params.boundary) {
    const children = splitMultipart(body, ct.params.boundary);
    children.forEach((child, i) => walkPart(child, [...path, i + 1], ctx));
    return;
  }

  // message/rfc822: descend so a forwarded message's text is still reachable.
  if (ct.full === 'message/rfc822') {
    walkPart(decodeTransfer(body, cte), [...path, 1], ctx);
    return;
  }

  const decoded = decodeTransfer(body, cte);
  const isInlineText = ct.type === 'text' && disposition !== 'attachment' && !filename;

  if (isInlineText && (ct.subtype === 'plain' || ct.subtype === 'html')) {
    const capped = decoded.subarray(0, MAX_TEXT_BYTES);
    const str = decodeCharset(capped, ct.params.charset);
    const target = ct.subtype === 'plain' ? 'text' : 'html';
    if (ctx[target] === null) {
      ctx[target] = str;
      if (decoded.length > MAX_TEXT_BYTES) ctx.truncated[target] = true;
    }
    return;
  }

  ctx.attachments.push({
    partPath,
    filename: filename ? decodeWords(filename) : null,
    contentType: ct.full,
    size: decoded.length,
    disposition: disposition || 'attachment',
    contentId: (headerGet(headers, 'content-id') || '').replace(/^<|>$/g, '') || null,
  });
}

/**
 * Parse a raw RFC 5322 message into the shape the API returns.
 * Never throws on malformed input — a garbage message yields empty fields, not a 500.
 */
export function parseMessage(raw) {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || '');
  const { headerText } = splitHeadersBody(buf);
  const headers = parseHeaders(headerText);

  const ctx = { text: null, html: null, attachments: [], parts: [], count: 0, truncated: { text: false, html: false }, truncatedTree: false };
  try {
    walkPart(buf, [1], ctx);
  } catch (e) {
    ctx.parseError = e.message;
  }

  return {
    headers: headers.map((h) => ({ name: h.name, value: decodeWords(h.value) })),
    subject: decodeWords(headerGet(headers, 'subject') || ''),
    from: decodeWords(headerGet(headers, 'from') || ''),
    to: decodeWords(headerGet(headers, 'to') || ''),
    cc: decodeWords(headerGet(headers, 'cc') || ''),
    replyTo: decodeWords(headerGet(headers, 'reply-to') || ''),
    date: headerGet(headers, 'date'),
    messageId: headerGet(headers, 'message-id'),
    text: ctx.text,
    html: ctx.html,
    attachments: ctx.attachments,
    parts: ctx.parts,
    truncated: ctx.truncated,
    ...(ctx.truncatedTree ? { truncatedTree: true } : {}),
    ...(ctx.parseError ? { parseError: ctx.parseError } : {}),
  };
}

/**
 * Walk to one part and return it UNDECODED: the exact bytes of the whole entity —
 * its headers, the blank line, and its body — as they were transmitted.
 *
 * WHY THIS IS SEPARATE FROM getPart(). getPart returns the decoded BODY, which is what
 * you want for an attachment and precisely what you must not use for a signature.
 * RFC 3156 §5 signs "the entire contents of the [signed] MIME entity", headers
 * included, byte for byte as sent. Verifying against a base64-decoded, header-stripped
 * body always fails — and it fails as `invalid`, i.e. it reports every correctly
 * signed message as tampered with. That is our bug wearing an accusation.
 *
 * The bytes are exact because splitMultipart() returns subarrays of the original
 * buffer, and it already excludes the CRLF that precedes a boundary line (RFC 2046:
 * that CRLF belongs to the delimiter, not to the part). No copy, no normalisation.
 */
export function getRawPart(raw, wantPath) {
  const found = locatePart(raw, wantPath);
  return found ? found.raw : null;
}

/**
 * Extract one MIME part's decoded bytes by the partPath that parseMessage() reported.
 * Returns null when the path does not resolve.
 */
export function getPart(raw, wantPath) {
  const found = locatePart(raw, wantPath);
  if (!found) return null;
  const { ct, cte, dparams, body } = found;
  return {
    contentType: ct.full,
    filename: (dparams.filename || ct.params.name) ? decodeWords(dparams.filename || ct.params.name) : null,
    data: decodeTransfer(body, cte),
  };
}

// Shared walk for both accessors above. Returns the raw entity plus everything already
// parsed on the way, so neither caller re-parses headers it has in hand.
function locatePart(raw, wantPath) {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || '');
  const target = String(wantPath || '').split('.').map(Number);
  if (!target.length || target.some((n) => !Number.isInteger(n) || n < 1)) return null;

  let current = buf;
  let path = [1];
  let depth = 0;

  for (;;) {
    if (++depth > MAX_DEPTH) return null;
    const { headerText, body } = splitHeadersBody(current);
    const headers = parseHeaders(headerText);
    const ct = parseContentType(headerGet(headers, 'content-type'));
    const cte = headerGet(headers, 'content-transfer-encoding');
    const cd = headerGet(headers, 'content-disposition') || '';
    const dparams = parseParams(cd.includes(';') ? cd.slice(cd.indexOf(';') + 1) : '');

    if (path.length === target.length && path.every((v, i) => v === target[i])) {
      return { raw: current, headers, ct, cte, dparams, body };
    }

    const nextIndex = target[path.length];
    if (!nextIndex) return null;

    if (ct.type === 'multipart' && ct.params.boundary) {
      const children = splitMultipart(body, ct.params.boundary);
      const child = children[nextIndex - 1];
      if (!child) return null;
      current = child;
      path = [...path, nextIndex];
      continue;
    }
    if (ct.full === 'message/rfc822') {
      // Descending through a forwarded message DECODES it, so from here down the
      // "exact transmitted bytes" property is relative to the decoded inner message —
      // which is the right frame: a signature inside a forwarded message covers the
      // inner message's own octets.
      current = decodeTransfer(body, cte);
      path = [...path, 1];
      continue;
    }
    return null;
  }
}
