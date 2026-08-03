/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: '#FFFFFF', // Brand white
          card:    '#FFFFFF',
          soft:    'rgba(22, 25, 26, 0.04)',
          softer:  'rgba(22, 25, 26, 0.08)',
          line:    'rgba(22, 25, 26, 0.12)',
          'line-strong': '#16191A',
        },
        accent: {
          DEFAULT: '#36FE35',
          soft:    '#36FE35',
          glow:    '#36FE35',
        },
        text: {
          DEFAULT: '#16191A', // Brand ink
          dim:     'rgba(22, 25, 26, 0.75)',
          muted:   'rgba(22, 25, 26, 0.55)',
        },
      },
      fontFamily: {
        display: ['"Dotective"', '"Fraunces"', 'Georgia', 'serif'],
        sans: ['"Switzer"', '"Hanken"', '"Inter"', 'system-ui', 'sans-serif'],
        serif: ['"Fraunces"', '"Merriweather"', 'Georgia', 'serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      boxShadow: {
        brutal: '6px 6px 0px 0px rgba(0,0,0,1)',
        'brutal-sm': '4px 4px 0px 0px rgba(0,0,0,1)',
        'brutal-green': '6px 6px 0px 0px #36FE35',
        glow: 'none',
        'glow-strong': 'none',
      },
    },
  },
  plugins: [],
};