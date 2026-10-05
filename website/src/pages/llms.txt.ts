// llms.txt (https://llmstxt.org): a plain-text index of the docs for AI
// assistants, which people increasingly ask instead of searching.
//
// Generated rather than written by hand, for the same reason the wiki is: a
// hand-kept index drifts. Every entry comes from the sidebar and each page's
// own title and description, and the build fails if the two disagree: a
// sidebar link with no page, or a page that no sidebar entry reaches.
//
// Built at /docs/llms.txt; the Pages workflow also copies it to the site root,
// where the convention expects it.
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { sidebar } from '../sidebar.mjs';

const SITE = 'https://www.flareover.com/docs';

// Pages that are deliberately not in the navigation.
const UNLISTED = new Set(['404']);

export const GET: APIRoute = async () => {
  const pages = new Map((await getCollection('docs')).map((e) => [e.id, e.data]));
  const listed = new Set<string>();

  const sections = sidebar.map(({ label, items }) => {
    const lines = items.map(({ link }) => {
      const id = link.replace(/^\/|\/$/g, '') || 'index';
      const page = pages.get(id);
      if (!page) throw new Error(`llms.txt: sidebar links ${link}, but there is no docs page "${id}"`);
      listed.add(id);
      return `- [${page.title}](${SITE}${link}): ${page.description}`;
    });
    return `## ${label}\n\n${lines.join('\n')}`;
  });

  const orphans = [...pages.keys()].filter((id) => !listed.has(id) && !UNLISTED.has(id));
  if (orphans.length) throw new Error(`llms.txt: pages not in the sidebar: ${orphans.join(', ')}`);

  const home = pages.get('index');
  const body = [
    '# flareover',
    `> ${home?.description}`,
    'flareover reads a live Cloudflare zone and generates the equivalent configuration for a self-hosted stack (Caddy, caddy-waf, PowerDNS, CertMate, MinIO) on EU infrastructure. Every setting gets one verdict: AUTO (a proven equivalent is generated), ASK (one yes/no, then AUTO) or MANUAL (surfaced, never guessed). It is a single Go binary, AGPL-3.0, with no telemetry. Source: https://github.com/fabriziosalmi/flareover',
    ...sections,
    '## Optional\n\n- [Questions and answers](https://github.com/fabriziosalmi/flareover/discussions): GitHub Discussions\n- [Changelog](https://github.com/fabriziosalmi/flareover/blob/main/CHANGELOG.md): what changed in each release',
  ].join('\n\n');

  return new Response(body + '\n', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
};
