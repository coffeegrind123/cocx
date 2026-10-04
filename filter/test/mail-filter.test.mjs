#!/usr/bin/env node
// Proves the mail filter junks the mail it was written for AND leaves real mail alone.
//
// The false-positive cases are the point of this file. A junk filter that only gets
// tested on junk is untested: every "it caught the spam" result is worthless without a
// control proving it discriminates. So the ham cases here are deliberately adversarial —
// a personal email that names a conflict, an abuse report that QUOTES the scam verbatim,
// and a cold enquiry from a gmail address — because each one is what a naive keyword
// blocklist would destroy.
//
// Run:  node filter/test/mail-filter.test.mjs   (or: make test)
//
// The junk fixtures are SYNTHETIC reconstructions of real advance-fee and SEO-outreach
// mail: names, addresses and domains are invented, but every signal the rules key on —
// header shape, money skeleton, pretext, steering address, the exact pitch phrasing —
// is preserved, because a paraphrase that drops the real phrasing is what hid a gap once
// ("I visited your website" was matched; the real mail said "I recently reviewed your").

import { classify, loadRules, addressOf, htmlToText } from '../mail-filter.js';
import { parseMessage } from '../mime-parse.js';

const DOMAIN = 'example.com';
const LOCALS = [`admin@${DOMAIN}`, `abuse@${DOMAIN}`, `postmaster@${DOMAIN}`];
const OWN = [DOMAIN];
const rules = loadRules();

let pass = 0, fail = 0;
const check = (name, cond, detail = '') => {
  if (cond) { pass++; console.log(`  ok    ${name}`); }
  else { fail++; console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`); }
};

const mk = (headers, body) => parseMessage(Buffer.from(`${headers.trim()}\r\n\r\n${body}`, 'utf8'));
const verdict = (msg) => classify(msg, rules, LOCALS, OWN);
const show = (v) => `score=${v.score} cats=[${v.categories.join(',')}]${v.allowed ? ` allowed=${v.allowed}` : ''}`;

// ---------------------------------------------------------------- JUNK: advance-fee
// Shape of a real Gaza-pretext 419: blast headers (To == From, placeholder name), the
// storage-facility money skeleton, the rotating pretext, and a second freemail address
// in the body that replies are steered to.
const SCAM_BODY = `Dear Friend:
My name is Yusuf Haddad. I use this opportunity to seek an honest assistant from you.
regarding the long Palestinian conflict with Israel. Father and siblings have all been killed.
You must know father is Karim Haddad A senior Hamas official.
I moved to a city called Rafah. The IDF soldiers have destroyed everything here by bombs.
My father was a foreign currency exchanger, IDF soldiers came and loot cash when they bomb our
office in west-bank with Millions of shekels, which is our local currency.
Before the bombing, I had transported some of the boxes out of the country for safety, through
an AID driver who deposited it in a storage facility outside the country.
Please contact me on this email address for further details: haddad.yusuf.private@gmail.com
Sincerely.
Yusuf Haddad.`;

const SCAM_FROM = 'yusufhaddadhelp.desk@gmail.com';
const scam = mk(`From: <${SCAM_FROM}>
To: Recipients <${SCAM_FROM}>
Subject: Urgent Help Needed.
Date: Sat, 1 Aug 2026 14:45:46 +0200
Content-Type: text/plain; charset=utf-8`, SCAM_BODY);

console.log('junk cases');
{
  const v = verdict(scam);
  check('the advance-fee mail is junked', v.junk, show(v));
  check('  ...on structural evidence, not just words', v.categories.includes('structural'), v.categories.join(','));
  check('  ...and on the money skeleton, not just the pretext', v.categories.includes('advance_fee'), v.categories.join(','));
  check('  ...it would still be junked with every crisis word removed',
    (() => {
      const stripped = mk(`From: <a@gmail.com>
To: Recipients <a@gmail.com>
Subject: Urgent Help Needed.`, SCAM_BODY
        .replace(/palestinian|israel|hamas|idf|rafah|west-bank|shekels|bomb\w*|killed/gi, 'redacted'));
      return verdict(stripped).junk;
    })(),
    'the pretext lexicon must be supporting evidence, not the load-bearing signal');
}

// HTML-only body: the same message with its text part stripped must score identically.
{
  const html = mk(`From: <${SCAM_FROM}>
To: Recipients <${SCAM_FROM}>
Subject: Urgent Help Needed.
Content-Type: text/html; charset=utf-8`, `<html><body><p>${SCAM_BODY.replace(/\n/g, '<br>')}</p></body></html>`);
  check('the HTML-only variant is junked too', verdict(html).junk, show(verdict(html)));
}

// SEO/backlink outreach — the other half of what a public admin@ receives. The pitch
// wording is kept exactly as such mail arrives; only the sender and domain are invented.
{
  const seo = mk(`From: Priya Menon <priyamenon.seo.org@gmail.com>
To: "admin" <admin@${DOMAIN}>
Subject: Regarding your Example.com`, `Dear Example.com Team,

I recently reviewed your Example.com and noticed it isn't ranking well on Google for your service-related searches, which is a missed opportunity, as top sites attract far more leads and visibility.

With the right SEO strategies, we can boost your ranking, attract targeted visitors, and convert them into customers. Let's get you to page 1.

Reply to this email or share your contact details to discuss further.

Best Regards
Priya Menon
Marketing Consultant`);
  const v = verdict(seo);
  check('the SEO pitch is junked', v.junk, show(v));
  check('  ...by a maxed-out category convicting alone', v.soloed === 'seo_outreach', `soloed=${v.soloed}`);
}

// ------------------------------------------------------------------- KEEP: controls
console.log('\nham controls (the cases a keyword blocklist would destroy)');

// 1. Our own contact-form relay — allowlisted by domain, must never be scored at all.
{
  const v = verdict(mk(`From: admin@${DOMAIN}
To: admin@${DOMAIN}
Subject: [contact] Advertising enquiry`, `Name: Someone
Message: We would like to discuss urgent advertising, please contact me on this email
address for further details. Budget in the millions of dollars.`));
  check('our own contact-form relay is never junked', !v.junk && v.allowed, show(v));
  // ...and that allow comes from ownDomains, not from anything in the shipped rules.
  const bare = classify(mk(`From: admin@${DOMAIN}
To: admin@${DOMAIN}
Subject: x`, 'hello'), rules, LOCALS, []);
  check('  ...the shipped rules allowlist no domain of their own', !bare.allowed, show(bare));
}

// 2. A real person naming a conflict. The whole reason crisis_pretext is capped and
//    gated behind minCategories.
{
  const v = verdict(mk(`From: Reader <someone@gmail.com>
To: admin@${DOMAIN}
Subject: forum thread`, `Hi, one of the threads on your forum is called "gaza war 2026" and is an
israel vs palestine flame war. Is that allowed? Some of us find it distasteful. Thanks.`));
  check('personal email naming a live conflict is kept', !v.junk, show(v));
}

// 3. An abuse report that quotes the scam in full. Without the negative signals this
//    scores exactly like the scam, because it CONTAINS the scam.
{
  const v = verdict(mk(`From: reporter <reporter@gmail.com>
To: abuse@${DOMAIN}
Subject: Reporting this fraud mail`, `I am reporting this spam that came from your network.

-----Original Message-----
${SCAM_BODY}`));
  check('an abuse report quoting the scam verbatim is kept', !v.junk, show(v));
}

// 3b. EVASION CONTROL for the case above. The quote split must not become a one-line
//     bypass: the same scam with a forward marker pasted at the top has to stay junked,
//     on its (unquotable) header evidence plus the capped quoted contribution.
{
  const v = verdict(mk(`From: <${SCAM_FROM}>
To: Recipients <${SCAM_FROM}>
Subject: Urgent Help Needed.`, `-----Original Message-----\n${SCAM_BODY}`));
  check('the scam is still junked when it hides behind a quote marker', v.junk, show(v));
}

// 4. A cold but legitimate business enquiry from a free-mail address.
{
  const v = verdict(mk(`From: Jane <jane@gmail.com>
To: admin@${DOMAIN}
Subject: Sponsorship`, `Hello, I run a small community team and wondered whether you sell
sponsorships. Could you send a rate card? Thanks, Jane`));
  check('cold sponsorship enquiry from gmail is kept', !v.junk, show(v));
}

// 5. A reply in an existing thread.
{
  const v = verdict(mk(`From: Sam <sam.example@gmail.com>
To: admin@${DOMAIN}
Subject: Re: IPv6 authentication fix
In-Reply-To: <abc@${DOMAIN}>`, `Looks good, thanks.`));
  check('an ordinary reply is kept', !v.junk, show(v));
}

// 6. An empty / malformed message must not crash and must not be junked.
{
  const v = verdict(parseMessage(Buffer.from('')));
  check('an empty message is kept and does not throw', !v.junk, show(v));
}

// ------------------------------------------------------------------------ helpers
console.log('\nhelpers');
check('addressOf unwraps a display name', addressOf('Recipients <a@b.com>') === 'a@b.com');
check('addressOf handles a bare address', addressOf('a@b.com') === 'a@b.com');
check('addressOf tolerates nothing', addressOf('') === null && addressOf(null) === null);
check('htmlToText drops tags and decodes entities', /AT&T here/.test(htmlToText('<p>AT&amp;T <b>here</b></p>')));
check('htmlToText discards script bodies', !/evil/.test(htmlToText('<script>evil()</script>hi')));

// A rules file whose threshold cannot be met would silently disable the filter.
check('threshold is reachable by the structural signals alone',
  Object.values(rules.structural).reduce((a, b) => a + b, 0) >= rules.threshold,
  `structural max=${Object.values(rules.structural).reduce((a, b) => a + b, 0)} threshold=${rules.threshold}`);
check('every category compiled at least one pattern',
  Object.values(rules.categories).every((c) => c.patterns.length > 0));

// The safety property the whole design rests on: the pretext lexicon can neither
// convict alone (solo) nor reach the threshold alone (cap < threshold).
check('crisis_pretext can never convict on its own',
  rules.categories.crisis_pretext.solo === false && rules.categories.crisis_pretext.cap < rules.threshold,
  `solo=${rules.categories.crisis_pretext.solo} cap=${rules.categories.crisis_pretext.cap} threshold=${rules.threshold}`);
check('a solo category must at least reach the threshold when maxed',
  Object.entries(rules.categories).every(([, c]) => !c.solo || c.cap + 1 >= rules.threshold));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
