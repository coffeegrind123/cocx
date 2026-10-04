// OpenPGP for mox's webmail — decryption, signature verification and key management,
// entirely in the browser.
//
// This file is NEW (added by the cocx OpenPGP patch series). Upstream mox contains no
// PGP code whatsoever, and will not: issue #23 is closed with the author agreeing that
// PGP "is best left to clients". This implementation agrees with him — mox's webmail IS
// a client, and that is exactly where the key lives here. Nothing PGP-related is sent
// to, stored on, or computed by the server.
//
// WHY THE PRIVATE KEY IS IN THE BROWSER
//   The alternative (keys in the mox account, decryption server-side) would mean
//   patching mox's config, account model and bstore schemas — a large patch across the
//   parts of mox that change most, i.e. one that breaks on every rebase. Keeping to the
//   webmail means one new file plus three tiny hunks, and it is also the stronger
//   posture: an attacker who takes the mail server still cannot read the mail, which is
//   the entire point of encrypting it in the first place.
//
//   The cost, stated plainly: the key lives in ONE browser profile. Move to another
//   machine and you must export/import it. There is no server-side copy to fall back
//   on, by design.
//
// SENDING
//   Also here. mox's SubmitMessage composes the MIME itself and cannot express
//   multipart/encrypted, so the series adds ONE field to it: `PGPEncrypted`, the armor.
//   Deliberately the armor rather than a whole raw MIME message — the server keeps
//   control of every header, so a compromised or buggy client cannot inject a Bcc, a
//   second body or a forged Date into a message this server DKIM-signs and sends under
//   our domain's reputation. The plaintext entity is built and encrypted here; the
//   server wraps the armor as RFC 3156 and never sees the content.
//
// WHAT IS DELIBERATELY NOT HERE
//   Key discovery (WKD, Autocrypt, keyservers): a correspondent's key has to be imported
//   by hand. Automatic discovery means trusting a key that arrived over the network,
//   which needs a verification workflow to be worth anything — a separate piece of work,
//   not a smaller version of this one.

import { dom, style, attr } from '../lib'
import { css, styles } from './lib'
import * as api from './api'

// openpgp.js is loaded lazily from mox's own /openpgp.js and is untyped here on
// purpose: vendoring its .d.ts would add ~200 KB of types to a build that gains
// nothing from them, and every call below is exercised at runtime by a real message.
// The `any` is the honest annotation for "third-party global we load on demand".
type OpenPGP = any

// ---------------------------------------------------------------- lazy loader

let openpgpPromise: Promise<OpenPGP> | null = null

// Loaded ONLY when a PGP message is actually opened (or the key UI is used). A normal
// mailbox session never fetches it. This is why it is a separate file rather than part
// of webmail.js: mox INLINES webmail.js into the HTML of every page load, so bundling
// openpgp would add ~400 KB to every single request, cached by nobody.
const loadOpenPGP = (): Promise<OpenPGP> => {
	if (openpgpPromise) {
		return openpgpPromise
	}
	openpgpPromise = new Promise<OpenPGP>((resolve, reject) => {
		const s = document.createElement('script')
		s.src = 'openpgp.js'
		s.onload = () => {
			const g = (window as any).openpgp
			if (g) {
				resolve(g)
			} else {
				reject(new Error('openpgp.js loaded but did not define a global'))
			}
		}
		s.onerror = () => reject(new Error('could not load openpgp.js from the server'))
		document.head.appendChild(s)
	})
	return openpgpPromise
}

// ---------------------------------------------------------------- key storage

export interface StoredKey {
	fingerprint: string
	keyID: string
	uids: string[]
	emails: string[]
	isOwn: boolean
	// Always S2K-passphrase-encrypted when present. An unprotected private key is
	// re-encrypted before it is stored — see importPrivate().
	privateArmored?: string
	publicArmored: string
	trust: 'own' | 'verified' | 'unverified'
	addedAt: number
}

const DB_NAME = 'moxpgp'
const DB_STORE = 'keys'

// Opening the keyring, SELF-HEALING if the object store is missing.
//
// The obvious version — open at version 1 and create the store in onupgradeneeded —
// has a trap: if the database already exists at version 1 but WITHOUT the store, no
// upgrade is triggered, so the store is never created and every read throws
// NotFoundError forever. That state is reachable from an upgrade that was interrupted
// midway, from another script on this origin opening the same database name, or from a
// future version bump that is later rolled back. It was hit for real during testing.
//
// So: open with NO version (whatever exists), and if the store is absent, reopen one
// version higher to force an upgrade that creates it. A fresh profile takes the same
// path — the first open creates an empty database, the second adds the store.
const idb = (): Promise<IDBDatabase> => new Promise((resolve, reject) => {
	const first = indexedDB.open(DB_NAME)
	first.onerror = () => reject(first.error || new Error('indexeddb open failed'))
	first.onsuccess = () => {
		const db = first.result
		if (db.objectStoreNames.contains(DB_STORE)) {
			resolve(db)
			return
		}
		const version = db.version + 1
		// The old connection must be closed or the upgrade blocks forever.
		db.close()
		const second = indexedDB.open(DB_NAME, version)
		second.onupgradeneeded = () => {
			if (!second.result.objectStoreNames.contains(DB_STORE)) {
				second.result.createObjectStore(DB_STORE, { keyPath: 'fingerprint' })
			}
		}
		second.onsuccess = () => resolve(second.result)
		second.onerror = () => reject(second.error || new Error('indexeddb upgrade failed'))
		second.onblocked = () => reject(new Error('indexeddb upgrade blocked by another tab — close other mox tabs'))
	}
})

const idbAll = async (): Promise<StoredKey[]> => {
	const db = await idb()
	return new Promise((resolve, reject) => {
		const req = db.transaction(DB_STORE, 'readonly').objectStore(DB_STORE).getAll()
		req.onsuccess = () => resolve((req.result || []) as StoredKey[])
		req.onerror = () => reject(req.error || new Error('indexeddb read failed'))
	})
}

const idbPut = async (k: StoredKey): Promise<void> => {
	const db = await idb()
	return new Promise((resolve, reject) => {
		const tx = db.transaction(DB_STORE, 'readwrite')
		tx.objectStore(DB_STORE).put(k)
		tx.oncomplete = () => resolve()
		tx.onerror = () => reject(tx.error || new Error('indexeddb write failed'))
	})
}

const idbDelete = async (fpr: string): Promise<void> => {
	const db = await idb()
	return new Promise((resolve, reject) => {
		const tx = db.transaction(DB_STORE, 'readwrite')
		tx.objectStore(DB_STORE).delete(fpr)
		tx.oncomplete = () => resolve()
		tx.onerror = () => reject(tx.error || new Error('indexeddb delete failed'))
	})
}

// Decrypted private keys, memory only, cleared on reload. Never written anywhere.
const unlocked = new Map<string, any>()

export const pgpLocked = () => unlocked.size === 0

export const pgpLockAll = () => {
	unlocked.clear()
}

// ---------------------------------------------------------------- key helpers

const emailsOf = (key: any): string[] => {
	const out: string[] = []
	for (const uid of key.getUserIDs()) {
		const m = /<([^>]+)>/.exec(uid)
		const addr = (m ? m[1] : uid).trim().toLowerCase()
		if (addr.includes('@') && !out.includes(addr)) {
			out.push(addr)
		}
	}
	return out
}

const summarize = (key: any, isOwn: boolean, trust: StoredKey['trust'], privateArmored?: string): StoredKey => ({
	fingerprint: key.getFingerprint().toUpperCase(),
	keyID: key.getKeyID().toHex().toUpperCase(),
	uids: key.getUserIDs(),
	emails: emailsOf(key),
	isOwn: isOwn,
	publicArmored: key.toPublic().armor(),
	privateArmored: privateArmored,
	trust: trust,
	addedAt: Date.now(),
})

export const pgpListKeys = (): Promise<StoredKey[]> => idbAll()

export const pgpImportPublic = async (armored: string): Promise<StoredKey> => {
	const openpgp = await loadOpenPGP()
	const key = await openpgp.readKey({ armoredKey: armored })
	// Arrives as `unverified` always. A key that came over the network — pasted from an
	// email, fetched from a keyserver — is an OFFER of an identity, never proof of one.
	// Promoting it is a separate, explicit act (see the keyring UI).
	const k = summarize(key, false, 'unverified')
	await idbPut(k)
	return k
}

export const pgpImportPrivate = async (armored: string, passphrase: string): Promise<StoredKey> => {
	const openpgp = await loadOpenPGP()
	if (passphrase.length < 8) {
		throw new Error('passphrase must be at least 8 characters')
	}
	let key = await openpgp.readPrivateKey({ armoredKey: armored })
	// Three cases, one destination: whatever arrives, what gets STORED is encrypted
	// under this passphrase. An unprotected key pasted in here would otherwise sit in
	// IndexedDB as usable secret material that any script on this origin could read.
	if (key.isDecrypted()) {
		key = await openpgp.encryptKey({ privateKey: key, passphrase: passphrase })
	} else {
		// Verifies the passphrase actually opens it before we commit it to storage —
		// otherwise the first thing the operator learns is that their key is unusable.
		await openpgp.decryptKey({ privateKey: key, passphrase: passphrase })
	}
	const k = summarize(key, true, 'own', key.armor())
	await idbPut(k)
	return k
}

export const pgpGenerate = async (name: string, email: string, passphrase: string): Promise<{ key: StoredKey, revocationCertificate: string }> => {
	const openpgp = await loadOpenPGP()
	if (passphrase.length < 8) {
		throw new Error('passphrase must be at least 8 characters')
	}
	const res = await openpgp.generateKey({
		userIDs: [{ name: name, email: email }],
		passphrase: passphrase,
		// ECC over the LEGACY curve25519 encoding, and v4 keys, on purpose. openpgp 6
		// can emit RFC 9580 v6 keys, which GnuPG 2.4 and Thunderbird's RNP cannot read
		// at all — a key nobody can encrypt to is worse than having no key. v6Keys
		// currently defaults to false; pinning it means an upstream default flip cannot
		// silently start minting unusable keys.
		type: 'ecc',
		curve: 'curve25519Legacy',
		format: 'object',
		config: { v6Keys: false },
	})
	const k = summarize(res.privateKey, true, 'own', res.privateKey.armor())
	await idbPut(k)
	return { key: k, revocationCertificate: res.revocationCertificate }
}

export const pgpDeleteKey = (fpr: string): Promise<void> => {
	unlocked.delete(fpr)
	return idbDelete(fpr)
}

export const pgpSetTrust = async (fpr: string, trust: StoredKey['trust']): Promise<void> => {
	const all = await idbAll()
	const k = all.find(x => x.fingerprint === fpr)
	if (k) {
		k.trust = trust
		await idbPut(k)
	}
}

/**
 * Try one passphrase against every stored private key.
 *
 * Applies to all of them because a rotated keyring is normal — old mail stays encrypted
 * to the old key forever — and reports partial success honestly rather than as either
 * "worked" or "failed".
 */
export const pgpUnlock = async (passphrase: string): Promise<{ opened: string[], failed: string[] }> => {
	const openpgp = await loadOpenPGP()
	const keys = (await idbAll()).filter(k => k.privateArmored)
	if (keys.length === 0) {
		throw new Error('no private key stored in this browser')
	}
	const opened: string[] = []
	const failed: string[] = []
	for (const k of keys) {
		try {
			const priv = await openpgp.readPrivateKey({ armoredKey: k.privateArmored })
			unlocked.set(k.fingerprint, await openpgp.decryptKey({ privateKey: priv, passphrase: passphrase }))
			opened.push(k.fingerprint)
		} catch {
			failed.push(k.fingerprint)
		}
	}
	if (opened.length === 0) {
		throw new Error('incorrect passphrase')
	}
	return { opened: opened, failed: failed }
}

const verificationKeys = async (): Promise<any[]> => {
	const openpgp = await loadOpenPGP()
	const out: any[] = []
	for (const k of await idbAll()) {
		try {
			out.push(await openpgp.readKey({ armoredKey: k.publicArmored }))
		} catch {
			// One unreadable row must not make every message unverifiable.
		}
	}
	return out
}

// ---------------------------------------------------------------- detection

export type PgpKind = 'encrypted' | 'signed'

export interface PgpInfo {
	kind: PgpKind
	// The parts are mox's own api.Part, which carry byte offsets into the raw message —
	// see fetchRaw() for why that is the whole trick.
	ciphertext?: api.Part
	signed?: api.Part
	signature?: api.Part
}

const ctype = (p: api.Part) => (p.MediaType + '/' + p.MediaSubType).toLowerCase()
const ctparam = (p: api.Part, name: string) => String((p.ContentTypeParams || {})[name] || '').toLowerCase()

/**
 * Classify a part tree against RFC 3156. STRUCTURAL, not a filename or content-type
 * guess: the tempting shortcut ("is there an application/octet-stream containing BEGIN
 * PGP MESSAGE") cannot tell an encrypted message from a SIGNED one — whose signature
 * part is also armor — nor from an ordinary mail that happens to carry a .asc
 * attachment somebody forwarded.
 *
 *   multipart/encrypted; protocol="application/pgp-encrypted"
 *     [0] application/pgp-encrypted   "Version: 1"
 *     [1] the ciphertext
 *
 *   multipart/signed; protocol="application/pgp-signature"
 *     [0] the signed entity, covered byte-for-byte as transmitted
 *     [1] application/pgp-signature
 */
export const pgpDetect = (p: api.Part | null | undefined): PgpInfo | null => {
	if (!p) {
		return null
	}
	const kids = p.Parts || []
	if (ctype(p) === 'multipart/encrypted' && ctparam(p, 'protocol') === 'application/pgp-encrypted' && kids.length >= 2) {
		if (ctype(kids[0]) === 'application/pgp-encrypted') {
			return { kind: 'encrypted', ciphertext: kids[1] }
		}
	}
	if (ctype(p) === 'multipart/signed' && ctparam(p, 'protocol') === 'application/pgp-signature' && kids.length >= 2) {
		const sig = kids[kids.length - 1]
		if (ctype(sig) === 'application/pgp-signature') {
			return { kind: 'signed', signed: kids[0], signature: sig }
		}
	}
	// Nested (forwarded, or list-processed) mail puts the encrypted part one level down.
	// Worth finding — but the caller is told nothing different, because from the
	// reader's point of view the encrypted part is still what they want to see.
	for (const kid of kids) {
		const hit = pgpDetect(kid)
		if (hit) {
			return hit
		}
	}
	return null
}

// ---------------------------------------------------------------- raw bytes

// A hostile message must not be able to make the tab allocate without bound. mox's own
// SMTPMaxMessageSize default is 100 MB; this is the display cap, not a protocol one.
const MAX_RAW_BYTES = 32 * 1024 * 1024

/**
 * The raw message, sliced to one part.
 *
 * This is where mox's ParsedMessage earns its keep: every api.Part carries
 * HeaderOffset / BodyOffset / EndOffset into the raw file, so the exact octets of any
 * part are addressable without reimplementing a MIME splitter for the OUTER message.
 *
 * For a signature that is not a convenience, it is a correctness requirement: RFC 3156
 * §5 signs the signed entity's HEADERS AND BODY exactly as transmitted, so verification
 * must run over `HeaderOffset..EndOffset` and not over anything a parser has decoded.
 * Verifying decoded bytes fails as "invalid", i.e. it accuses every correctly signed
 * message of being forged.
 */
const fetchRaw = async (msgID: number): Promise<Uint8Array> => {
	const resp = await fetch('msg/' + msgID + '/raw')
	if (!resp.ok) {
		throw new Error('could not fetch the raw message (HTTP ' + resp.status + ')')
	}
	const buf = await resp.arrayBuffer()
	if (buf.byteLength > MAX_RAW_BYTES) {
		throw new Error('message is too large to decrypt in the browser')
	}
	return new Uint8Array(buf)
}

const slice = (raw: Uint8Array, from: number, to: number): Uint8Array => raw.subarray(from, to)

// ---------------------------------------------------------------- minimal MIME

// The DECRYPTED payload of a PGP/MIME message is a complete MIME entity, and the server
// never sees it — so unlike the outer message there are no offsets to lean on and it
// has to be parsed here. Deliberately minimal: enough for what mail clients actually
// produce inside an encrypted part (text, alternative, mixed, attachments), with hard
// caps, and no attempt at the long tail. Anything it cannot parse degrades to showing
// the decrypted bytes as text, which is always better than an error.

interface MimeNode {
	contentType: string
	params: { [k: string]: string }
	disposition: string
	filename: string
	body: Uint8Array
	children: MimeNode[]
}

const MAX_MIME_PARTS = 100
const MAX_MIME_DEPTH = 10

const findCRLFCRLF = (b: Uint8Array): number => {
	for (let i = 0; i + 3 < b.length; i++) {
		if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) {
			return i
		}
	}
	// Bare-LF messages exist in the wild and are not worth failing over.
	for (let i = 0; i + 1 < b.length; i++) {
		if (b[i] === 10 && b[i + 1] === 10) {
			return i
		}
	}
	return -1
}

const latin1 = (b: Uint8Array): string => {
	let s = ''
	for (let i = 0; i < b.length; i++) {
		s += String.fromCharCode(b[i])
	}
	return s
}

const decodeBase64 = (s: string): Uint8Array => {
	const clean = s.replace(/[^A-Za-z0-9+/=]/g, '')
	const bin = atob(clean)
	const out = new Uint8Array(bin.length)
	for (let i = 0; i < bin.length; i++) {
		out[i] = bin.charCodeAt(i)
	}
	return out
}

const decodeQP = (s: string): Uint8Array => {
	const unfolded = s.replace(/=\r?\n/g, '')
	const out: number[] = []
	for (let i = 0; i < unfolded.length; i++) {
		if (unfolded[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(unfolded.substr(i + 1, 2))) {
			out.push(parseInt(unfolded.substr(i + 1, 2), 16))
			i += 2
		} else {
			out.push(unfolded.charCodeAt(i) & 0xff)
		}
	}
	return new Uint8Array(out)
}

const parseParams = (s: string): { [k: string]: string } => {
	const params: { [k: string]: string } = {}
	const re = /([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*=\s*("([^"]*)"|[^;]*)/g
	let m: RegExpExecArray | null
	while ((m = re.exec(s)) !== null) {
		params[m[1].toLowerCase()] = (m[3] !== undefined ? m[3] : m[2]).trim()
	}
	return params
}

const splitMultipart = (body: Uint8Array, boundary: string): Uint8Array[] => {
	const text = latin1(body)
	const delim = '--' + boundary
	const parts: Uint8Array[] = []
	let pos = 0
	let start = -1
	for (;;) {
		const at = text.indexOf(delim, pos)
		if (at < 0) {
			break
		}
		if (at !== 0 && text[at - 1] !== '\n') {
			pos = at + delim.length
			continue
		}
		if (start >= 0) {
			let end = at
			// The CRLF before a boundary belongs to the delimiter, not to the part.
			if (end > 0 && text[end - 1] === '\n') { end-- }
			if (end > 0 && text[end - 1] === '\r') { end-- }
			parts.push(body.subarray(start, end))
		}
		if (text.substr(at + delim.length, 2) === '--') {
			break
		}
		const nl = text.indexOf('\n', at + delim.length)
		if (nl < 0) {
			break
		}
		start = nl + 1
		pos = start
	}
	return parts
}

const parseEntity = (bytes: Uint8Array, depth: number, budget: { n: number }): MimeNode => {
	const node: MimeNode = { contentType: 'text/plain', params: {}, disposition: '', filename: '', body: bytes, children: [] }
	if (depth > MAX_MIME_DEPTH || budget.n++ > MAX_MIME_PARTS) {
		return node
	}
	const sep = findCRLFCRLF(bytes)
	if (sep < 0) {
		return node
	}
	const headerText = latin1(bytes.subarray(0, sep))
		.replace(/\r?\n[ \t]/g, ' ')       // unfold
	let body = bytes.subarray(sep + (bytes[sep] === 13 ? 4 : 2))

	let cte = ''
	for (const line of headerText.split(/\r?\n/)) {
		const idx = line.indexOf(':')
		if (idx <= 0) {
			continue
		}
		const name = line.slice(0, idx).trim().toLowerCase()
		const value = line.slice(idx + 1).trim()
		if (name === 'content-type') {
			const semi = value.indexOf(';')
			node.contentType = (semi < 0 ? value : value.slice(0, semi)).trim().toLowerCase()
			node.params = parseParams(semi < 0 ? '' : value.slice(semi + 1))
		} else if (name === 'content-transfer-encoding') {
			cte = value.trim().toLowerCase()
		} else if (name === 'content-disposition') {
			const semi = value.indexOf(';')
			node.disposition = (semi < 0 ? value : value.slice(0, semi)).trim().toLowerCase()
			node.filename = parseParams(semi < 0 ? '' : value.slice(semi + 1))['filename'] || ''
		}
	}
	if (!node.filename && node.params['name']) {
		node.filename = node.params['name']
	}

	if (node.contentType.startsWith('multipart/') && node.params['boundary']) {
		for (const child of splitMultipart(body, node.params['boundary'])) {
			node.children.push(parseEntity(child, depth + 1, budget))
		}
		node.body = new Uint8Array(0)
		return node
	}

	if (cte === 'base64') {
		body = decodeBase64(latin1(body))
	} else if (cte === 'quoted-printable') {
		body = decodeQP(latin1(body))
	}
	node.body = body
	return node
}

const decodeText = (b: Uint8Array, charset: string): string => {
	try {
		return new TextDecoder(charset || 'utf-8', { fatal: false }).decode(b)
	} catch {
		return new TextDecoder('utf-8', { fatal: false }).decode(b)
	}
}

// Depth-first pick of the parts a reader wants: the first text/plain, the first
// text/html, and everything else as an attachment.
const collect = (n: MimeNode, out: { text: string | null, html: string | null, attachments: MimeNode[] }) => {
	if (n.children.length > 0) {
		for (const c of n.children) {
			collect(c, out)
		}
		return
	}
	const isAttachment = n.disposition === 'attachment' || n.filename !== ''
	if (!isAttachment && n.contentType === 'text/plain' && out.text === null) {
		out.text = decodeText(n.body, n.params['charset'])
	} else if (!isAttachment && n.contentType === 'text/html' && out.html === null) {
		out.html = decodeText(n.body, n.params['charset'])
	} else if (n.body.length > 0) {
		out.attachments.push(n)
	}
}

// ---------------------------------------------------------------- rendering

// FOUR states, and they must be four DIFFERENT things on screen. "Signed" on its own is
// not a verdict: a valid signature from a key nobody has checked, and a valid signature
// from a key the operator compared by phone, are different claims, and rendering them
// alike teaches the reader to ignore the banner entirely — at which point the whole
// feature is decoration.
//
// mox has no error/danger background token (only warning and success), so `bad` reuses
// the warning background and is distinguished by --underlineRed, which is mox's OWN
// colour for authentication and security results — the one it already uses to mark a
// message that arrived without TLS. Borrowing it keeps this inside mox's vocabulary and
// its light/dark theming instead of hardcoding a red that breaks in one of them.
const banner = { padding: '.4em .6em', borderRadius: '.25em', marginBottom: '.5em' }
const sigStyle = {
	ok: css('pgpSigOk', { ...banner, backgroundColor: styles.successBackground }),
	warn: css('pgpSigWarn', { ...banner, backgroundColor: styles.warningBackgroundColor }),
	bad: css('pgpSigBad', {
		...banner,
		backgroundColor: styles.warningBackgroundColor,
		borderLeft: '4px solid', borderLeftColor: styles.underlineRed, fontWeight: 'bold',
	}),
	none: css('pgpSigNone', { ...banner, backgroundColor: styles.backgroundColorMild }),
}

interface SigResult { verified: boolean, keyID: string, fingerprint: string, reason: string, uids: string[] }

/**
 * Resolve openpgp's verification results.
 *
 * EVERY signature is awaited. openpgp models each `verified` as a promise that THROWS
 * on an invalid signature, so the obvious `await sigs[0].verified` both ignores the rest
 * and lets a message carrying one good and one bad signature report as good. Each
 * unawaited rejection is also an unhandled promise rejection.
 */
const resolveSigs = async (sigs: any[], keys: any[]): Promise<SigResult[]> => {
	const out: SigResult[] = []
	for (const s of sigs || []) {
		const keyID = s.keyID.toHex().toUpperCase()
		let fingerprint = ''
		let uids: string[] = []
		for (const k of keys) {
			const ids = [k.getKeyID().toHex().toUpperCase()].concat(k.getSubkeys().map((sk: any) => sk.getKeyID().toHex().toUpperCase()))
			if (ids.includes(keyID)) {
				fingerprint = k.getFingerprint().toUpperCase()
				uids = k.getUserIDs()
			}
		}
		let verified = false
		let reason = ''
		try {
			await s.verified
			verified = true
		} catch (err) {
			// "we hold no key for this signer" and "this signature is forged" are
			// completely different facts and must never render the same way.
			const msg = err instanceof Error ? err.message : String(err)
			reason = /no signature found|could not find signing key|unknown key/i.test(msg) ? 'no_key' : 'invalid'
		}
		out.push({ verified: verified, keyID: keyID, fingerprint: fingerprint, reason: reason, uids: uids })
	}
	return out
}

const signatureBanner = async (sigs: SigResult[]): Promise<HTMLElement> => {
	if (sigs.length === 0) {
		return dom.div(sigStyle.none, 'Not signed — nothing proves who sent this.')
	}
	const bad = sigs.filter(s => !s.verified && s.reason === 'invalid')
	if (bad.length > 0) {
		return dom.div(sigStyle.bad, 'BAD SIGNATURE — this message does not match its signature. Treat it as altered or forged.')
	}
	const good = sigs.filter(s => s.verified)
	if (good.length === 0) {
		return dom.div(sigStyle.warn, 'Signed by an unknown key (' + sigs.map(s => s.keyID).join(', ') + ') — import that key to check the signature.')
	}
	const stored = await idbAll()
	const allTrusted = good.every(s => {
		const k = stored.find(x => x.fingerprint === s.fingerprint)
		return k && (k.trust === 'verified' || k.trust === 'own')
	})
	const who = good.map(s => s.uids[0] || s.keyID).join(', ')
	return allTrusted
		? dom.div(sigStyle.ok, 'Signed by ' + who + ' — key verified out of band.')
		: dom.div(sigStyle.warn, 'Signed by ' + who + ' — valid signature, but this key has never been verified out of band. It proves the same sender as last time, not who they are.')
}

export interface PgpRenderCtx {
	msgID: number
	pm: api.ParsedMessage
	content: HTMLElement
	scroll: HTMLElement
	mode: HTMLElement
}

/**
 * Render a PGP message, replacing mox's normal body rendering.
 *
 * Returns false when the message is not PGP, or when there is nothing useful we can do
 * with it — in which case the caller renders normally and the reader still sees the
 * message as it arrived, which for an encrypted mail means the armor. Failing SOFT is
 * deliberate: anyone on the internet can email this mailbox, and a thrown error here
 * would let a malformed armor block make a message impossible to open at all.
 */
export const pgpRender = async (ctx: PgpRenderCtx): Promise<boolean> => {
	const info = pgpDetect(ctx.pm.Part)
	if (!info) {
		return false
	}

	const box = dom.div(style({ padding: '1em', maxWidth: '50em' }))
	const show = (...kids: any[]) => {
		dom._kids(box, ...kids)
		dom._kids(ctx.scroll, box)
		dom._kids(ctx.content, ctx.scroll)
		dom._kids(ctx.mode)
	}

	show(dom.div(sigStyle.none, info.kind === 'encrypted' ? 'Encrypted message — decrypting…' : 'Signed message — verifying…'))

	try {
		const openpgp = await loadOpenPGP()
		const raw = await fetchRaw(ctx.msgID)
		const keys = await verificationKeys()

		if (info.kind === 'signed') {
			const signedPart = info.signed!
			const sigPart = info.signature!
			// HeaderOffset, not BodyOffset: RFC 3156 signs the entity including its
			// headers, exactly as transmitted.
			const signedBytes = slice(raw, signedPart.HeaderOffset, signedPart.EndOffset)
			const sigText = latin1(slice(raw, sigPart.BodyOffset, sigPart.EndOffset))
			const verified = await openpgp.verify({
				message: await openpgp.createMessage({ binary: signedBytes }),
				signature: await openpgp.readSignature({ armoredSignature: sigText }),
				verificationKeys: keys,
				format: 'binary',
			})
			const sigs = await resolveSigs(verified.signatures, keys)
			const inner = parseEntity(signedBytes, 0, { n: 0 })
			show(await signatureBanner(sigs), renderBody(inner))
			return true
		}

		// Encrypted.
		if (unlocked.size === 0) {
			show(
				dom.div(sigStyle.warn, 'This message is encrypted. Unlock your private key to read it.'),
				dom.clickbutton('Unlock…', async function click() {
					if (await unlockPrompt()) {
						await pgpRender(ctx)
					}
				}),
			)
			return true
		}

		const ctPart = info.ciphertext!
		const ctBytes = slice(raw, ctPart.BodyOffset, ctPart.EndOffset)
		const ctText = latin1(ctBytes)
		const message = ctText.includes('-----BEGIN PGP MESSAGE-----')
			? await openpgp.readMessage({ armoredMessage: ctText })
			: await openpgp.readMessage({ binaryMessage: ctBytes })

		const res = await openpgp.decrypt({
			message: message,
			decryptionKeys: Array.from(unlocked.values()),
			verificationKeys: keys,
			// binary, NOT utf8: the payload is a MIME entity whose parts carry their own
			// charsets and transfer encodings. Decoding it as UTF-8 here would corrupt
			// every non-UTF-8 part and every binary attachment before the parser sees it,
			// and openpgp's utf8 mode also normalises newlines, which breaks any
			// signature inside.
			format: 'binary',
		})
		const sigs = await resolveSigs(res.signatures, keys)
		const inner = parseEntity(new Uint8Array(res.data), 0, { n: 0 })
		show(
			dom.div(sigStyle.ok, 'Decrypted in your browser.'),
			await signatureBanner(sigs),
			renderBody(inner),
		)
		return true
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err)
		show(
			dom.div(sigStyle.bad, 'Could not ' + (info.kind === 'encrypted' ? 'decrypt' : 'verify') + ' this message.'),
			dom.div(style({ marginBottom: '.5em' }), /session key decryption failed|No decryption key/i.test(msg)
				? 'It is probably encrypted to a key this browser does not hold.'
				: msg),
			dom.clickbutton('Show the raw message instead', function click() {
				window.open('msg/' + ctx.msgID + '/raw', '_blank')
			}),
		)
		return true
	}
}

const renderBody = (inner: MimeNode): HTMLElement => {
	const picked: { text: string | null, html: string | null, attachments: MimeNode[] } = { text: null, html: null, attachments: [] }
	collect(inner, picked)

	// If it parsed as nothing useful, show the decrypted bytes as text rather than an
	// empty pane. A partially-understood message beats a blank one.
	if (picked.text === null && picked.html === null && inner.body.length > 0) {
		picked.text = decodeText(inner.body, inner.params['charset'])
	}

	const kids: any[] = []
	if (picked.text !== null) {
		kids.push(dom.div(dom._class('mono'), style({ whiteSpace: 'pre-wrap' }), picked.text))
	}
	if (picked.html !== null) {
		// TEXT FIRST, HTML ONLY ON REQUEST, AND ONLY INSIDE A SANDBOX.
		//
		// mox renders ordinary HTML mail through a server-side route whose response
		// carries a strict CSP (webmail.go sets default-src 'none' for /msg/<id>/html).
		// A decrypted body cannot use that route — the server never sees the plaintext —
		// so the containment has to be built here instead: a srcdoc iframe with an EMPTY
		// sandbox attribute, which blocks scripts, forms, popups, top-level navigation
		// and same-origin access all at once. Decrypting something does not make it
		// trustworthy; if anything, mail someone bothered to encrypt deserves more
		// suspicion, not less.
		const html = picked.html
		const frame = dom.iframe(
			attr.title('HTML part of the decrypted message, sandboxed'),
			style({ width: '100%', height: '40em', border: '1px solid ' + styles.borderColor, backgroundColor: 'white' }),
		) as HTMLIFrameElement
		frame.setAttribute('sandbox', '')
		const btn = dom.clickbutton('Show HTML part (sandboxed)', function click(e: MouseEvent) {
			frame.srcdoc = html
			const b = e.target as HTMLElement
			b.replaceWith(frame)
		})
		kids.push(dom.div(style({ marginTop: '.5em' }), btn))
	}
	if (picked.attachments.length > 0) {
		kids.push(dom.div(
			style({ marginTop: '1em', paddingTop: '.5em', borderTop: '1px solid ' + styles.borderColor }),
			dom.div(style({ marginBottom: '.25em' }), 'Attachments inside the encrypted part:'),
			picked.attachments.map(a => {
				// Served from a blob: URL built here, because these bytes exist only in
				// this tab — the server has never seen them and has no route that could
				// serve them.
				const name = a.filename || 'attachment'
				const url = URL.createObjectURL(new Blob([a.body as BlobPart], { type: a.contentType }))
				return dom.div(dom.a(attr.href(url), attr.download(name), name),
					' — ' + a.contentType + ', ' + a.body.length + ' bytes')
			}),
		))
	}
	return dom.div(...kids)
}

// ---------------------------------------------------------------- key discovery
//
// Three ways to find a correspondent's key, in descending order of how much they tell
// you. NONE of them establishes trust: everything discovered lands as `unverified` and
// still needs a fingerprint compared out of band. Discovery answers "is there a key
// claiming to be this address", never "is this really them".
//
//   Autocrypt  a header on mail they already sent us. No network, no CORS, and it is
//              how most first contacts actually arrive.
//   WKD        published by the address's own domain, so it is the most authoritative.
//              Needs the server proxy (webmail/pgpwkd.go) because WKD hosts send no
//              CORS headers — measured, not assumed.
//   HKPS       keys.openpgp.org, which is only as good as its verification, but does
//              send `access-control-allow-origin: *` so the browser can query it.

export type DiscoverySource = 'autocrypt' | 'wkd' | 'hkps'

export interface Discovered {
	source: DiscoverySource
	fingerprint: string
	uids: string[]
	emails: string[]
	armored: string
	matchesAddress: boolean
}

const summarizeDiscovered = async (key: any, source: DiscoverySource, address: string): Promise<Discovered> => ({
	source: source,
	fingerprint: key.getFingerprint().toUpperCase(),
	uids: key.getUserIDs(),
	emails: emailsOf(key),
	armored: key.toPublic().armor(),
	// A key found for one address whose user IDs name a DIFFERENT one is not
	// automatically wrong — people have multiple addresses — but it is worth saying out
	// loud rather than importing silently.
	matchesAddress: emailsOf(key).includes(address.toLowerCase()),
})

/**
 * Parse an `Autocrypt:` header value.
 *
 * The header is `addr=…; prefer-encrypt=…; keydata=<base64>`, folded across lines. Only
 * a header whose `addr` matches the sender counts — an Autocrypt header naming someone
 * else is either a forwarded message or an attempt to get us to associate a key with an
 * address its owner never claimed.
 */
export const parseAutocrypt = (value: string, senderAddress: string): { keydata: Uint8Array, preferEncrypt: string } | null => {
	// Unfold first: the header is long and always arrives wrapped.
	const cleaned = value.replace(/\r?\n[ \t]/g, '')
	let addr = ''
	let keydata = ''
	let preferEncrypt = ''
	for (const part of cleaned.split(';')) {
		const eq = part.indexOf('=')
		if (eq === -1) {
			continue
		}
		const k = part.slice(0, eq).trim().toLowerCase()
		const v = part.slice(eq + 1).trim()
		if (k === 'addr') {
			addr = v.toLowerCase()
		} else if (k === 'keydata') {
			keydata = v.replace(/\s+/g, '')
		} else if (k === 'prefer-encrypt') {
			preferEncrypt = v.toLowerCase()
		}
	}
	if (!addr || !keydata || addr !== senderAddress.toLowerCase()) {
		return null
	}
	try {
		const bin = atob(keydata)
		const out = new Uint8Array(bin.length)
		for (let i = 0; i < bin.length; i++) {
			out[i] = bin.charCodeAt(i)
		}
		return { keydata: out, preferEncrypt: preferEncrypt }
	} catch {
		return null
	}
}

/** WKD, via the server proxy. Returns null when the domain publishes nothing. */
const discoverWKD = async (address: string): Promise<Discovered | null> => {
	const openpgp = await loadOpenPGP()
	try {
		const resp = await fetch('wkd?addr=' + encodeURIComponent(address))
		if (!resp.ok) {
			return null
		}
		const buf = new Uint8Array(await resp.arrayBuffer())
		if (buf.length === 0) {
			return null
		}
		// The proxy deliberately does not validate that the bytes are a key — mox has no
		// OpenPGP implementation. This is that check. A host answering 200 with an error
		// page is a MISS, not a hit; without parsing, "HTTP 200" would be mistaken for
		// "found a key".
		return await summarizeDiscovered(await openpgp.readKey({ binaryKey: buf }), 'wkd', address)
	} catch {
		return null
	}
}

/** keys.openpgp.org. Queried directly — it sends permissive CORS headers. */
const discoverHKPS = async (address: string): Promise<Discovered | null> => {
	const openpgp = await loadOpenPGP()
	try {
		const resp = await fetch('https://keys.openpgp.org/vks/v1/by-email/' + encodeURIComponent(address), {
			headers: { Accept: 'application/pgp-keys' },
		})
		if (!resp.ok) {
			return null
		}
		const text = await resp.text()
		if (!text.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
			return null
		}
		return await summarizeDiscovered(await openpgp.readKey({ armoredKey: text }), 'hkps', address)
	} catch {
		return null
	}
}

/**
 * Look an address up everywhere, in parallel, and return every distinct key found.
 *
 * All results are returned rather than just the "best" one: when two sources disagree
 * that is the single most interesting thing discovery can tell you, and silently
 * preferring one would hide it.
 */
// ---------------------------------------------------------------------------------------
// The EMITTING half of Autocrypt. parseAutocrypt() above is the consuming half; this is
// what lets anyone reply to us encrypted.
//
// ⚠ THIS RUNS ON EVERY SEND, ENCRYPTED OR NOT, AND THAT IS THE ENTIRE POINT. Autocrypt
// exists to solve the bootstrap problem: the first mail to a new correspondent is always
// plaintext, because neither side has the other's key yet. A header attached only to
// encrypted mail could therefore never travel, and encryption could never start. The
// message stays exactly as readable as it was — the header carries a key, not ciphertext.
//
// ⚠ THE SERVER BUILDS THE HEADER, NOT US. We return only the base64 keydata; api.go emits
// `Autocrypt: addr=…; prefer-encrypt=…; keydata=…` with addr taken from the AUTHENTICATED
// sender. That split is deliberate and matches the reason PGPEncrypted is armor rather
// than a raw MIME message: a browser must not be able to put a header line into a message
// this server signs with our DKIM key. Handing over a finished header would reopen exactly
// that door, newline injection included.
//
// ⚠ keydata IS THE BINARY KEY, base64'd — NOT the armor. Armor is itself base64 wrapped in
// BEGIN/END lines and a checksum; base64-ing the armored text yields something no client
// can parse, and it fails silently as "no Autocrypt header matched sender" rather than as
// an error. openpgp.js `write()` gives the binary form; `armor()` does not.
//
// Never throws. A missing or broken own key means NO header and a perfectly normal email —
// opportunistic key distribution must never be able to block an ordinary send.
export const pgpAutocryptKeydata = async (fromAddress: string): Promise<string> => {
	try {
		const own = (await idbAll()).filter(k => k.isOwn)
		if (own.length === 0) {
			return ''
		}
		// Autocrypt carries exactly ONE key. With several own keys, prefer the one whose
		// user IDs actually claim the From address — a header whose addr= does not match
		// the sender is ignored by every implementation, so picking the wrong key is the
		// same as sending nothing, but quieter.
		// ⚠ `emails`, matched EXACTLY — not a substring of `uids`. Autocrypt requires addr=
		// to equal the From address, so an exact match on the parsed email is the actual
		// question being asked; a substring test over user-ID strings would happily match
		// "admin@example.com" inside "notadmin@example.com.example".
		const want = (fromAddress || '').trim().toLowerCase()
		let chosen: StoredKey | undefined
		if (want) {
			chosen = own.find(k => (k.emails || []).some(e => e.toLowerCase() === want))
		}
		if (!chosen) {
			chosen = own[0]
		}
		// openpgp.js is loaded LAZILY and bound per function — there is no module-level
		// `openpgp` in this file (see loadOpenPGP above, and all ten other call sites).
		// Omitting this line compiles nowhere and fails as `TS2304: Cannot find name
		// 'openpgp'` only once mox's own tsc runs, which is on the deploy host.
		const openpgp = await loadOpenPGP()
		const key = await openpgp.readKey({ armoredKey: chosen.publicArmored })
		const bytes: Uint8Array = key.toPublic().write()
		// Chunked: String.fromCharCode(...bytes) on a multi-KB key overflows the argument
		// limit and throws, which would silently drop the header on exactly the large keys
		// most likely to be real.
		let bin = ''
		for (let i = 0; i < bytes.length; i++) {
			bin += String.fromCharCode(bytes[i])
		}
		return btoa(bin)
	} catch {
		return ''
	}
}

export const pgpDiscover = async (address: string): Promise<Discovered[]> => {
	const results = await Promise.all([discoverWKD(address), discoverHKPS(address)])
	const out: Discovered[] = []
	for (const r of results) {
		if (r && !out.some(x => x.fingerprint === r.fingerprint)) {
			out.push(r)
		}
	}
	return out
}

/**
 * The Autocrypt offer shown above an incoming message.
 *
 * Runs for EVERY message, not just encrypted ones — the whole point is bootstrapping,
 * and someone's first mail to us is usually plaintext with an Autocrypt header on it.
 * It renders nothing at all unless there is a header we do not already have a key for,
 * so an ordinary inbox looks exactly as it did before.
 */
export const pgpAutocryptNotice = async (ctx: PgpRenderCtx): Promise<void> => {
	try {
		const headers = ctx.pm.Headers || {}
		let raw = ''
		for (const k of Object.keys(headers)) {
			if (k.toLowerCase() === 'autocrypt') {
				const v = headers[k]
				if (v && v.length > 0) {
					raw = v[v.length - 1]
				}
			}
		}
		if (!raw) {
			return
		}
		// api.Address is {Name, User, Host} — Host is the domain in ASCII. (Note this is
		// NOT api.MessageAddress, which is the {User, Domain:{ASCII,Unicode}} shape used
		// elsewhere in the webmail; picking the wrong one is a compile error, usefully.)
		const env = ctx.pm.Part && ctx.pm.Part.Envelope
		const from = env && env.From && env.From.length > 0 ? (env.From[0].User + '@' + env.From[0].Host) : ''
		if (!from) {
			return
		}
		const parsed = parseAutocrypt(raw, from)
		if (!parsed) {
			return
		}
		const openpgp = await loadOpenPGP()
		const key = await openpgp.readKey({ binaryKey: parsed.keydata })
		const fpr = key.getFingerprint().toUpperCase()

		const stored = await idbAll()
		if (stored.some(k => k.fingerprint === fpr)) {
			return                      // already known; say nothing
		}
		const conflicting = stored.find(k => k.emails.includes(from.toLowerCase()))

		const bar = dom.div(
			conflicting ? sigStyle.warn : sigStyle.none,
			style({ margin: '0 1em .5em' }),
			conflicting
				? 'This sender attached a DIFFERENT OpenPGP key to this message than the one you hold for them. That can mean they rotated keys — or that this message is not from them. Compare the fingerprint before replacing anything.'
				: 'This sender attached an OpenPGP key (Autocrypt). Importing it lets you send them encrypted mail.',
			dom.div(dom._class('mono'), style({ fontSize: '.9em', margin: '.25em 0' }),
				(fpr.match(/.{1,4}/g) || []).join(' ')),
			dom.clickbutton(conflicting ? 'Import as an additional key' : 'Import key', async function click(e: MouseEvent) {
				try {
					await pgpImportPublic(key.toPublic().armor())
					const b = e.target as HTMLElement
					b.replaceWith(dom.span('Imported as unverified — compare the fingerprint with them before trusting it.'))
				} catch (err) {
					window.alert(err instanceof Error ? err.message : String(err))
				}
			}),
		)
		// Inserted as a SIBLING above the message body rather than into it, so mox's own
		// rendering of the message is untouched and this survives its re-renders.
		if (ctx.content.parentElement) {
			ctx.content.parentElement.insertBefore(bar, ctx.content)
		}
	} catch {
		// A malformed Autocrypt header is not an error worth showing anyone; it just
		// means no offer. Anyone on the internet can put one on a message.
	}
}

// ---------------------------------------------------------------- sending

// Composing an encrypted message needs a complete MIME entity to encrypt. mox builds
// the OUTER message (headers, the multipart/encrypted wrapper) from the armor we hand
// it — see SubmitMessage.PGPEncrypted — but the plaintext inside is ours to construct,
// because by definition the server must never see it.

const CRLF = '\r\n'

const b64wrap = (b64: string): string => (b64.match(/.{1,76}/g) || []).join(CRLF)

const bytesToB64 = (b: Uint8Array): string => {
	let s = ''
	for (let i = 0; i < b.length; i++) {
		s += String.fromCharCode(b[i])
	}
	return btoa(s)
}

// A boundary that cannot occur in base64 or in OpenPGP armor, so it can never collide
// with the content it delimits.
const newBoundary = (): string => {
	const r = new Uint8Array(18)
	crypto.getRandomValues(r)
	return '--=_' + Array.from(r).map(x => x.toString(16).padStart(2, '0')).join('')
}

export interface PgpAttachment { filename: string, dataURI: string }

/**
 * The plaintext MIME entity: a complete entity (its own Content-Type header plus body),
 * not a bare body, because RFC 3156 encrypts an entity and the recipient hands the
 * decrypted bytes straight to a MIME parser.
 *
 * Base64 for every part rather than 8bit or quoted-printable: it sidesteps the 998-octet
 * SMTP line limit and any transport mangling, and it costs nothing on content that is
 * about to be compressed and encrypted anyway.
 */
const buildInnerMime = (textBody: string, attachments: PgpAttachment[]): Uint8Array => {
	const enc = new TextEncoder()
	const textPart = 'Content-Type: text/plain; charset=utf-8' + CRLF +
		'Content-Transfer-Encoding: base64' + CRLF + CRLF +
		b64wrap(bytesToB64(enc.encode(textBody))) + CRLF

	if (attachments.length === 0) {
		return enc.encode(textPart)
	}

	const b = newBoundary()
	let out = 'Content-Type: multipart/mixed; boundary="' + b + '"' + CRLF + CRLF +
		'--' + b + CRLF + textPart
	for (const a of attachments) {
		// api.File.DataURI is "data:<content-type>;base64,<data>" — already the encoding
		// a MIME part wants, so it is re-emitted rather than decoded and re-encoded.
		const comma = a.dataURI.indexOf(',')
		const head = a.dataURI.slice(0, comma)
		const data = a.dataURI.slice(comma + 1)
		let ct = head.replace(/^data:/, '').replace(/;base64$/, '')
		if (!ct) {
			ct = 'application/octet-stream'
		}
		const name = a.filename.replace(/["\\\r\n]/g, '_')
		out += '--' + b + CRLF +
			'Content-Type: ' + ct + '; name="' + name + '"' + CRLF +
			'Content-Transfer-Encoding: base64' + CRLF +
			'Content-Disposition: attachment; filename="' + name + '"' + CRLF + CRLF +
			b64wrap(data) + CRLF
	}
	out += '--' + b + '--' + CRLF
	return enc.encode(out)
}

const addrOf = (s: string): string => {
	const m = /<([^>]+)>/.exec(s)
	return (m ? m[1] : s).trim().toLowerCase()
}

export interface PgpRecipientState { address: string, key: StoredKey | null, usable: boolean, reason: string }

/**
 * Which recipients we can encrypt to. Drives the compose UI's per-recipient indicator
 * and, more importantly, the refusal: a message encrypted to only some of its recipients
 * would silently arrive as unreadable noise for the rest.
 *
 * Expiry and revocation are checked here rather than left to the encrypt call, because
 * "this key is dead" needs to be visible while composing, not as a failure on send.
 */
export const pgpRecipientStates = async (addresses: string[]): Promise<PgpRecipientState[]> => {
	const openpgp = await loadOpenPGP()
	const stored = await idbAll()
	const out: PgpRecipientState[] = []
	for (const raw of addresses) {
		const address = addrOf(raw)
		if (!address) {
			continue
		}
		const k = stored.find(x => x.emails.includes(address)) || null
		if (!k) {
			out.push({ address: address, key: null, usable: false, reason: 'no key' })
			continue
		}
		let usable = true
		let reason = k.trust === 'verified' || k.trust === 'own' ? 'verified' : 'unverified key'
		try {
			const key = await openpgp.readKey({ armoredKey: k.publicArmored })
			if (await key.isRevoked()) {
				usable = false
				reason = 'key revoked'
			} else {
				const exp = await key.getExpirationTime()
				if (exp instanceof Date && exp.getTime() < Date.now()) {
					usable = false
					reason = 'key expired'
				} else {
					await key.getEncryptionKey()
				}
			}
		} catch {
			usable = false
			reason = 'key unusable'
		}
		out.push({ address: address, key: k, usable: usable, reason: reason })
	}
	return out
}

/**
 * The compose window's recipient-key indicator, rendered here rather than in
 * webmail.ts — it keeps the upstream patch to a single call and puts the "look this
 * address up" affordance right where the problem is reported.
 */
export const pgpRenderRecipientStatus = async (addresses: string[], into: HTMLElement): Promise<void> => {
	if (addresses.length === 0) {
		dom._kids(into, '— add a recipient')
		return
	}
	dom._kids(into, '— checking keys…')
	let states: PgpRecipientState[]
	try {
		states = await pgpRecipientStates(addresses)
	} catch (err) {
		dom._kids(into, '— ' + (err instanceof Error ? err.message : String(err)))
		return
	}
	const bad = states.filter(s => !s.usable)
	if (bad.length === 0) {
		const unverified = states.filter(s => s.reason === 'unverified key').length
		dom._kids(into, '— key found for all ' + states.length + ' recipient(s)' +
			(unverified > 0 ? ' (' + unverified + ' not verified out of band)' : ''))
		return
	}
	dom._kids(into,
		dom.span('— no usable key for ' + bad.map(s => s.address + ' (' + s.reason + ')').join(', ') + ' '),
		dom.clickbutton('Look up…', async function click(e: MouseEvent) {
			const btn = e.target as HTMLElement
			btn.replaceWith(dom.span('searching…'))
			const found: string[] = []
			for (const s of bad) {
				const hits = await pgpDiscover(s.address)
				for (const h of hits) {
					await pgpImportPublic(h.armored)
					found.push(s.address + ' via ' + h.source + (h.matchesAddress ? '' : ' (user id does not match!)'))
				}
			}
			if (found.length === 0) {
				dom._kids(into, '— no key published for ' + bad.map(s => s.address).join(', ') +
					'. Ask them to send you one, or paste it in under PGP.')
				return
			}
			// Imported UNVERIFIED. Encryption will work, and the message will be
			// readable only by whoever holds that key — which is the thing the operator
			// has not yet confirmed is the person they mean.
			dom._kids(into, '— imported ' + found.join('; ') + ' — unverified; compare the fingerprint under PGP before trusting it.')
			await pgpRenderRecipientStatus(addresses, into)
		}),
	)
}

export interface PgpSubmitOpts {
	to: string[]
	cc: string[]
	bcc: string[]
	textBody: string
	attachments: PgpAttachment[]
}

/**
 * Encrypt a composed message and return the armor for SubmitMessage.PGPEncrypted.
 *
 * Throws with a message meant to be shown to the operator — the caller surfaces it and
 * nothing is sent. Refusing is the correct outcome for a missing key: sending it
 * unencrypted "as a fallback" would be the single worst thing this code could do.
 */
export const pgpEncryptForSubmit = async (o: PgpSubmitOpts): Promise<string> => {
	const openpgp = await loadOpenPGP()
	const recipients = o.to.concat(o.cc).concat(o.bcc)
	if (recipients.length === 0) {
		throw new Error('no recipients')
	}
	const states = await pgpRecipientStates(recipients)
	const bad = states.filter(s => !s.usable)
	if (bad.length > 0) {
		throw new Error('cannot encrypt to ' + bad.map(s => s.address + ' (' + s.reason + ')').join(', ') +
			'. Import a key for them, or turn encryption off.')
	}

	const keys: any[] = []
	for (const s of states) {
		keys.push(await openpgp.readKey({ armoredKey: s.key!.publicArmored }))
	}

	// ENCRYPT TO SELF, always. Without it the copy saved to Sent is encrypted only to
	// the recipient and we can never read our own sent mail again — unfixable after the
	// fact, and the sort of thing nobody notices until months later.
	const own = (await idbAll()).filter(k => k.isOwn)
	for (const k of own) {
		try {
			keys.push(await openpgp.readKey({ armoredKey: k.publicArmored }))
		} catch {
			// A broken own key must not stop the send; the recipient copy is still fine.
		}
	}
	if (own.length === 0) {
		throw new Error('no own key — generate or import one first, or the copy in Sent will be unreadable')
	}

	// Sign when we can. A signature is what makes encryption mean "from us" rather than
	// only "to them", so a locked key is worth one prompt before giving up on it.
	let signingKey: any = null
	if (unlocked.size === 0) {
		await unlockPrompt()
	}
	if (unlocked.size > 0) {
		signingKey = Array.from(unlocked.values())[0]
	} else if (!window.confirm('Your private key is locked, so this message cannot be signed — the recipient will not be able to tell it came from you.\n\nSend encrypted but unsigned?')) {
		throw new Error('cancelled')
	}

	const message = await openpgp.createMessage({ binary: buildInnerMime(o.textBody, o.attachments) })
	return await openpgp.encrypt({
		message: message,
		encryptionKeys: keys,
		signingKeys: signingKey ? [signingKey] : undefined,
		// Bcc is not blind on an encrypted message: every recipient's key ID is written
		// into the PKESK packets, so each of them can see the others exist. `wildcard`
		// replaces all of them with an all-zero key ID, which restores the property Bcc
		// is supposed to have. It costs recipients a trial decryption per key, so it is
		// only used when there is actually something to hide.
		wildcard: o.bcc.length > 0,
		format: 'armored',
	})
}

// ---------------------------------------------------------------- key UI

const unlockPrompt = async (): Promise<boolean> => {
	const pass = window.prompt('Passphrase for your PGP private key (stays in this browser):')
	if (!pass) {
		return false
	}
	try {
		const r = await pgpUnlock(pass)
		if (r.failed.length > 0) {
			window.alert('Unlocked ' + r.opened.length + ' of ' + (r.opened.length + r.failed.length) + ' keys. The rest use a different passphrase.')
		}
		return true
	} catch (err) {
		window.alert(err instanceof Error ? err.message : String(err))
		return false
	}
}

/**
 * The keyring pane, for mox's settings/menu area.
 *
 * Everything here is local to this browser profile. Stated in the UI, because the
 * difference between "my mail server has my key" and "this browser has my key" is the
 * whole security model and is not something a reader should have to infer.
 */
export const pgpKeysView = (): HTMLElement => {
	const list = dom.div()
	const root = dom.div(
		dom.h2('OpenPGP keys'),
		dom.p(style({ maxWidth: '45em' }),
			'Keys are stored in this browser only. The server never sees your private key and cannot read your encrypted mail. ',
			'Clearing this site\'s data, or using another browser or device, means importing the key again — there is no server-side copy.'),
		list,
	)

	const refresh = async () => {
		// A failed keyring read must not render as an EMPTY keyring. Those look
		// identical — "No keys yet." — and the difference between "you have no keys"
		// and "your keys cannot be read" is the difference between importing one and
		// investigating why storage is broken.
		let keys: StoredKey[]
		try {
			keys = await pgpListKeys()
		} catch (err) {
			dom._kids(list, dom.div(sigStyle.bad,
				'Could not read the keyring from this browser\'s storage: ' +
				(err instanceof Error ? err.message : String(err))))
			return
		}
		dom._kids(list,
			dom.div(style({ marginBottom: '1em' }),
				dom.clickbutton('Unlock…', async function click() { await unlockPrompt(); await refresh() }),
				' ',
				dom.clickbutton('Lock', function click() { pgpLockAll(); refresh() }),
				' ',
				dom.span(style({ marginLeft: '1em' }), pgpLocked() ? 'locked' : 'unlocked for this session'),
			),
			keys.length === 0 ? dom.div('No keys yet.') : keys.map(k => dom.div(
				style({ border: '1px solid ' + styles.borderColor, borderRadius: '.25em', padding: '.5em', marginBottom: '.5em' }),
				dom.div(dom.b(k.uids[0] || k.emails[0] || '(no user id)'),
					' ', dom.span(style({ opacity: '.7' }), k.isOwn ? '· own' : '· ' + k.trust),
					k.privateArmored ? dom.span(style({ opacity: '.7' }), ' · private') : []),
				// The full fingerprint, grouped in fours: comparing it out of band IS
				// the verification step, so it has to be readable aloud.
				dom.div(dom._class('mono'), style({ fontSize: '.9em', opacity: '.8' }),
					(k.fingerprint.match(/.{1,4}/g) || []).join(' ')),
				dom.div(style({ marginTop: '.35em' }),
					k.isOwn ? [] : dom.clickbutton(k.trust === 'verified' ? 'Mark unverified' : 'Mark verified', async function click() {
						if (k.trust !== 'verified' && !window.confirm('Confirm you have compared this fingerprint with its owner over a channel other than email:\n\n' + k.fingerprint)) {
							return
						}
						await pgpSetTrust(k.fingerprint, k.trust === 'verified' ? 'unverified' : 'verified')
						await refresh()
					}),
					' ',
					dom.clickbutton('Export public key', function click() {
						window.prompt('Public key — give this to people who want to write to you:', k.publicArmored)
					}),
					' ',
					dom.clickbutton('Delete', async function click() {
						// Irreversible AND retroactive: every message encrypted to this
						// key becomes unreadable, and there is no server-side copy to
						// restore from. Confirm by fingerprint, not by clicking OK.
						const want = k.fingerprint.slice(-8)
						const typed = window.prompt((k.privateArmored
							? 'Delete this PRIVATE key?\n\nEvery message encrypted to it becomes PERMANENTLY unreadable. There is no backup anywhere.\n\n'
							: 'Delete this key?\n\n') + 'Type the last 8 characters of the fingerprint to confirm:\n' + k.fingerprint)
						if (!typed || typed.trim().toUpperCase() !== want) {
							if (typed !== null) {
								window.alert('Fingerprint did not match — nothing was deleted.')
							}
							return
						}
						await pgpDeleteKey(k.fingerprint)
						await refresh()
					}),
				),
			)),
			dom.h3('Find someone\'s key'),
			(() => {
				const addr = dom.input(attr.type('email'), attr.placeholder('address@domain')) as HTMLInputElement
				const out = dom.div(style({ marginTop: '.35em' }))
				return dom.div(addr, ' ', dom.clickbutton('Look up', async function click() {
					const a = addr.value.trim()
					if (!a) {
						return
					}
					dom._kids(out, 'searching WKD and keys.openpgp.org…')
					try {
						const hits = await pgpDiscover(a)
						if (hits.length === 0) {
							dom._kids(out, 'No key published for ' + a + '. Ask them to send you one, or paste it in below.')
							return
						}
						dom._kids(out, hits.map(h => dom.div(
							style({ border: '1px solid ' + styles.borderColor, borderRadius: '.25em', padding: '.4em', marginTop: '.35em' }),
							dom.div(dom.b(h.uids[0] || a), ' — found via ' + h.source),
							// Shown BEFORE importing. Discovery proves a key exists at an
							// address, never that it belongs to the person meant, so the
							// fingerprint has to be visible at the moment of choosing.
							dom.div(dom._class('mono'), style({ fontSize: '.9em', opacity: '.8' }),
								(h.fingerprint.match(/.{1,4}/g) || []).join(' ')),
							h.matchesAddress ? [] : dom.div(sigStyle.warn,
								'This key\'s user IDs do not include ' + a + '. It may belong to someone else.'),
							dom.clickbutton('Import as unverified', async function click(e: MouseEvent) {
								await pgpImportPublic(h.armored)
								;(e.target as HTMLElement).replaceWith(dom.span('Imported — compare the fingerprint with them before trusting it.'))
								await refresh()
							}),
						)))
					} catch (err) {
						dom._kids(out, 'Lookup failed: ' + (err instanceof Error ? err.message : String(err)))
					}
				}), out)
			})(),
			dom.h3('Add a key'),
			(() => {
				const ta = dom.textarea(attr.rows('5'), style({ width: '100%' }),
					attr.placeholder('-----BEGIN PGP PUBLIC KEY BLOCK----- …   (a PRIVATE key block also needs the passphrase below)')) as HTMLTextAreaElement
				const pw = dom.input(attr.type('password'), attr.placeholder('passphrase (private keys only)')) as HTMLInputElement
				return dom.div(ta, dom.div(style({ marginTop: '.35em' }), pw, ' ',
					dom.clickbutton('Import', async function click() {
						try {
							if (ta.value.includes('PRIVATE KEY BLOCK')) {
								await pgpImportPrivate(ta.value, pw.value)
							} else {
								await pgpImportPublic(ta.value)
							}
							ta.value = ''
							pw.value = ''
							await refresh()
						} catch (err) {
							window.alert(err instanceof Error ? err.message : String(err))
						}
					})))
			})(),
			dom.h3('Generate a key'),
			(() => {
				const name = dom.input(attr.placeholder('Display name')) as HTMLInputElement
				const email = dom.input(attr.type('email'), attr.placeholder('address@domain')) as HTMLInputElement
				const pw = dom.input(attr.type('password'), attr.placeholder('passphrase (min 8, not stored)')) as HTMLInputElement
				return dom.div(name, ' ', email, ' ', pw, ' ',
					dom.clickbutton('Generate', async function click() {
						if (!window.confirm('Generate a new key for ' + email.value + '?\n\nThe passphrase is not stored anywhere. Lose it and everything encrypted to this key is gone.')) {
							return
						}
						try {
							const r = await pgpGenerate(name.value, email.value, pw.value)
							pw.value = ''
							// Shown ONCE and stored nowhere: it is the only way to revoke
							// the key if the passphrase is lost, and keeping it beside the
							// key would defeat the point of having it.
							window.prompt('Save this revocation certificate now — it is not stored and cannot be shown again:', r.revocationCertificate)
							await refresh()
						} catch (err) {
							window.alert(err instanceof Error ? err.message : String(err))
						}
					}))
			})(),
		)
	}
	refresh()
	return root
}
