// The docs navigation, in one place. astro.config.mjs hands it to Starlight,
// and src/pages/llms.txt.ts walks it to build the index for AI assistants, so
// a page added here reaches both and neither can list a page the other lacks.
// Links are relative to the site's base (/docs).
export const sidebar = [
  {
    label: 'Start here',
    items: [
      { label: 'Overview', link: '/' },
      { label: 'Installation', link: '/installation/' },
      { label: 'Quick start', link: '/quick-start/' },
    ],
  },
  {
    label: 'Concepts',
    items: [
      { label: 'The contract', link: '/the-contract/' },
      { label: 'Architecture', link: '/architecture/' },
      { label: 'Coverage matrix', link: '/coverage-matrix/' },
      { label: 'Sovereignty tiers', link: '/sovereignty-tiers/' },
    ],
  },
  {
    label: 'Guides',
    items: [
      { label: 'Keep your origin (WireGuard)', link: '/keep-your-origin/' },
      { label: 'Hardened Proxmox landing zone', link: '/hardened-deploy/' },
    ],
  },
  {
    label: 'Reference',
    items: [
      { label: 'CLI reference', link: '/cli-reference/' },
      { label: 'DNS targets', link: '/dns-targets/' },
      { label: 'Object storage', link: '/object-storage/' },
      { label: 'Deploy', link: '/deploy/' },
      { label: 'Security', link: '/security/' },
    ],
  },
  {
    label: 'Help',
    items: [
      { label: 'FAQ', link: '/faq/' },
      { label: 'Troubleshooting', link: '/troubleshooting/' },
    ],
  },
];
