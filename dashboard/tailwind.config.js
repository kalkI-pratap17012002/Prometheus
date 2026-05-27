/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          900: '#0b0d13',
          800: '#11141c',
          700: '#1a1e2a',
          600: '#252a39',
          500: '#363c4f',
          400: '#525a72',
          300: '#7a8197',
          200: '#a8afc1',
          100: '#d6dae3',
        },
      },
    },
  },
  plugins: [],
}
