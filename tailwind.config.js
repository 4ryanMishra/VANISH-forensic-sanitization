/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0B0F19',
        surface: '#111827',
        'surface-highlight': '#1F2937',
        primary: {
          DEFAULT: '#3B82F6',
          dark: '#1D4ED8',
          light: '#60A5FA',
        },
        danger: {
          DEFAULT: '#EF4444',
          dark: '#B91C1C',
        },
        warning: {
          DEFAULT: '#F59E0B',
          dark: '#D97706',
        },
        success: {
          DEFAULT: '#10B981',
          dark: '#047857',
        }
      }
    },
  },
  plugins: [],
}
