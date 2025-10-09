import type { Config } from 'tailwindcss';
import plugin from 'tailwindcss/plugin';

export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        success: 'hsl(var(--success))',
        warning: 'hsl(var(--warning))',
        error: 'hsl(var(--error))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))'
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))'
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))'
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))'
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))'
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))'
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))'
        }
      },
      boxShadow: {
        soft: '0 24px 60px -32px rgba(15, 23, 42, 0.45)',
        subtle: '0 12px 32px -24px rgba(15, 23, 42, 0.35)'
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)'
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' }
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' }
        }
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out'
      }
    }
  },
  plugins: [
    require('tailwindcss-animate'),
    plugin(({ addBase }) => {
      addBase({
        ':root': {
          '--background': 'var(--theme-background)',
          '--foreground': 'var(--theme-foreground)',
          '--card': 'var(--theme-card)',
          '--card-foreground': 'var(--theme-card-foreground)',
          '--popover': 'var(--theme-popover)',
          '--popover-foreground': 'var(--theme-popover-foreground)',
          '--primary': 'var(--theme-primary)',
          '--primary-foreground': 'var(--theme-primary-foreground)',
          '--secondary': 'var(--theme-secondary)',
          '--secondary-foreground': 'var(--theme-secondary-foreground)',
          '--muted': 'var(--theme-muted)',
          '--muted-foreground': 'var(--theme-muted-foreground)',
          '--accent': 'var(--theme-accent)',
          '--accent-foreground': 'var(--theme-accent-foreground)',
          '--destructive': 'var(--theme-destructive)',
          '--destructive-foreground': 'var(--theme-destructive-foreground)',
          '--border': 'var(--theme-border)',
          '--input': 'var(--theme-input)',
          '--ring': 'var(--theme-ring)',
          '--success': 'var(--theme-success)',
          '--warning': 'var(--theme-warning)',
          '--error': 'var(--theme-error)',
          '--radius': 'var(--radius)'
        }
      });
    })
  ]
} satisfies Config;
