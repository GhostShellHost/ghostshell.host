import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['var(--font-mono)', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        shell: {
          bg: '#0b0c10',
          card: '#12141b',
          accent: '#7c5cff',
          green: '#2ee59d',
          muted: '#aab3bf',
          line: '#252a35',
        },
      },
    },
  },
  plugins: [],
};

export default config;
