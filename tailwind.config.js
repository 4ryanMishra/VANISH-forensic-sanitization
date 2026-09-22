/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        // Foundation surfaces (warm bone / ivory / white)
        background: '#F6F6F2',
        surface: {
          DEFAULT: '#FFFFFF',
          subtle: '#EEEEEE',
          muted: '#E6E6E0',
          hover: '#F2F2EC',
        },
        // Borders
        border: {
          DEFAULT: '#DFE0D8',
          strong: '#C2C4B8',
          subtle: '#ECEEE6',
        },
        // Typography (charcoal / graphite hierarchy)
        charcoal: {
          DEFAULT: '#15171B',
          secondary: '#3D414D',
          muted: '#686D7C',
          faint: '#989DAA',
        },
        // Semantic Family: Forensics (Ultraviolet / Violet)
        forensic: {
          DEFAULT: '#6D28D9',
          dark: '#531CA8',
          light: '#8B5CF6',
          surface: '#F5F2FC',
          border: '#DDD6FE',
        },
        // Semantic Family: Sanitization & Destructive (Vermilion / Coral)
        vermilion: {
          DEFAULT: '#D9381E',
          dark: '#B0260F',
          light: '#F87171',
          surface: '#FFF2F0',
          border: '#FECACA',
        },
        // Semantic Family: Verified & Safe (Acidic Fresh Green / Forest)
        verified: {
          DEFAULT: '#16A34A',
          dark: '#15803D',
          light: '#4ADE80',
          surface: '#F0FDF4',
          border: '#BBF7D0',
        },
        // Semantic Family: Device & Telemetry (Cyan / Teal)
        telemetry: {
          DEFAULT: '#0891B2',
          dark: '#0E7490',
          light: '#22D3EE',
          surface: '#ECFEFF',
          border: '#BAE6FD',
        },
        // Semantic Family: Warning & Protected (Warm Amber)
        amber: {
          DEFAULT: '#D97706',
          dark: '#B45309',
          light: '#FBBF24',
          surface: '#FFFBEB',
          border: '#FDE68A',
        },
      },
      boxShadow: {
        'subtle': '0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.04)',
        'elevated': '0 4px 6px -1px rgba(0, 0, 0, 0.06), 0 2px 4px -2px rgba(0, 0, 0, 0.04)',
        'popover': '0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.04)',
      },
    },
  },
  plugins: [],
}

