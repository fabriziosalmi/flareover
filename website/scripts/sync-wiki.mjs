// Regenerate the GitHub wiki from the canonical docs in
// website/src/content/docs.
//
// The wiki used to be a hand-copied mirror. It was honest about it — Home.md
// says "kept as a mirror and may lag" — but it lagged in the way that matters:
// after v0.2.0/v0.3.0 its CLI-Reference was missing four flags and described
// exit codes that had changed, so the page a reader lands on from GitHub search
// disagreed with the binary.
//
// This project's answer to documentation drift everywhere else is to generate
// rather than to copy (the coverage matrix and the sovereignty tiers come from
// the engine, with tests that fail on drift). This applies the same rule to the
// wiki: one source, one command, no hand-copying.
//
//   node website/scripts/sync-wiki.mjs <path-to-wiki-clone>
//
// Home.md, _Sidebar.md and _Footer.md are hand-maintained wiki furniture and
// are never touched.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const docsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'content', 'docs');
const wikiDir = process.argv[2];
if (!wikiDir) {
  console.error('usage: node sync-wiki.mjs <path-to-wiki-clone>');
  process.exit(2);
}

// Pages the wiki owns. index.md becomes Home.md, which is hand-written.
const SKIP = new Set(['index.md']);

// Acronyms the slug loses. "cli-reference" must become "CLI-Reference", not
// "Cli-Reference", or every cross-link 404s.
const ACRONYMS = { cli: 'CLI', dns: 'DNS', faq: 'FAQ' };

/** slug ("cli-reference") -> wiki page name ("CLI-Reference"). */
function pageName(slug) {
  return slug
    .split('-')
    .map((w) => ACRONYMS[w] ?? w.charAt(0).toUpperCase() + w.slice(1))
    .join('-');
}

/** Convert one Starlight page to wiki markdown. */
function toWiki(src) {
  let title = '';
  let body = src;

  // 1. Frontmatter -> H1. Starlight renders the title from frontmatter; the
  //    wiki has no such mechanism, so it needs a real heading.
  const fm = body.match(/^---\n([\s\S]*?)\n---\n/);
  if (fm) {
    const m = fm[1].match(/^title:\s*"?(.*?)"?\s*$/m);
    if (m) title = m[1];
    body = body.slice(fm[0].length);
  }

  // 2. Starlight asides (:::note[Label] … :::) -> blockquotes, which is the
  //    closest thing GitHub-flavoured markdown has.
  body = body.replace(
    /^:::(note|tip|caution|danger)(?:\[([^\]]*)\])?\n([\s\S]*?)\n:::$/gm,
    (_, kind, label, content) => {
      const heading = label || kind.charAt(0).toUpperCase() + kind.slice(1);
      const quoted = content
        .split('\n')
        .map((l) => (l.trim() === '' ? '>' : `> ${l}`))
        .join('\n');
      return `> **${heading}**\n>\n${quoted}`;
    },
  );

  // 3. Site-absolute doc links -> wiki page names.
  body = body.replace(/\]\(\/docs\/([a-z0-9-]+)\/?(#[^)]*)?\)/g, (_, slug, hash) =>
    `](${pageName(slug)}${hash ?? ''})`,
  );
  // The docs root itself has no wiki equivalent; point at Home.
  body = body.replace(/\]\(\/docs\/?\)/g, '](Home)');

  return `${title ? `# ${title}\n` : ''}${body.replace(/^\n+/, '\n')}`;
}

let written = 0;
for (const file of readdirSync(docsDir).filter((f) => f.endsWith('.md')).sort()) {
  if (SKIP.has(file)) continue;
  const slug = file.replace(/\.md$/, '');
  const out = join(wikiDir, `${pageName(slug)}.md`);
  writeFileSync(out, toWiki(readFileSync(join(docsDir, file), 'utf8')));
  console.log(`  ${file} -> ${pageName(slug)}.md`);
  written++;
}
console.log(`synced ${written} page(s) into ${wikiDir}`);
