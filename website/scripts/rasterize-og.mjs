// Rasterize the Open Graph card (docs/og-image.svg) to PNG. SVG OG images are
// not rendered by several social/chat platforms (LinkedIn, Slack, …), so we ship
// a PNG for the crawlers. Generated from the SVG at deploy time, so it never
// drifts from the source art.
//
// Usage: node scripts/rasterize-og.mjs [out.png]   (default: docs/og-image.png)
import sharp from 'sharp';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = join(repoRoot, 'docs', 'og-image.svg');
const out = process.argv[2] || join(repoRoot, 'docs', 'og-image.png');

const svg = readFileSync(src);
await sharp(svg, { density: 220 })
  .resize(1200, 630, { fit: 'cover' })
  .png({ compressionLevel: 9 })
  .toFile(out);

console.log('wrote ' + out + ' (1200x630)');
