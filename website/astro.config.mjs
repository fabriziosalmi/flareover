// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://www.flareover.com',
  base: '/docs',
  outDir: './dist',
  integrations: [
    starlight({
      title: 'flareover',
      description:
        'Move your site off the orange cloud onto your own EU servers, without changing how it behaves. A deterministic, 0% false-positive migration engine.',
      logo: { src: './src/assets/logo-mark.svg', alt: 'flareover' },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/theme.css'],
      // Wraps Starlight's own footer to add the privacy notice link, so it
      // reaches every docs page instead of only the hand-written landing.
      components: {
        Footer: './src/components/Footer.astro',
      },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/fabriziosalmi/flareover' },
      ],
      editLink: {
        baseUrl: 'https://github.com/fabriziosalmi/flareover/edit/main/website/',
      },
      sidebar: [
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
      ],
    }),
  ],
});
