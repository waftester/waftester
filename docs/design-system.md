# WAFtester Design System

> Visual identity guidelines for all WAFtester output formats (HTML, PDF).

## Design Philosophy

WAFtester reports should look **authoritative and technical**, not generic. We follow the "Blueprint" aesthetic: deep slate/blue palette, monospace labels, precise borders, technical drawing feel.

## Color Palette

### Primary Accent
```css
--accent-primary: #0d9488;    /* Teal 600 - professional, not "AI purple" */
--accent-hover: #14b8a6;      /* Teal 500 */
--accent-muted: #5eead4;      /* Teal 300 */
```

### Severity Colors (ZAP-inspired)
```css
--severity-critical: #dc2626; /* Red 600 */
--severity-high: #ea580c;     /* Orange 600 */
--severity-medium: #ca8a04;   /* Yellow 600 */
--severity-low: #16a34a;      /* Green 600 */
--severity-info: #2563eb;     /* Blue 600 */
```

### Background & Text
```css
/* Light theme */
--bg-primary: #ffffff;
--bg-secondary: #f8fafc;      /* Slate 50 */
--bg-recessed: #f1f5f9;       /* Slate 100 */
--text-primary: #0f172a;      /* Slate 900 */
--text-secondary: #475569;    /* Slate 600 */
--text-dim: #94a3b8;          /* Slate 400 */
--border: #e2e8f0;            /* Slate 200 */

/* Dark theme */
--bg-primary-dark: #0f172a;   /* Slate 900 */
--bg-secondary-dark: #1e293b; /* Slate 800 */
--bg-recessed-dark: #334155;  /* Slate 700 */
--text-primary-dark: #f8fafc; /* Slate 50 */
--text-secondary-dark: #cbd5e1;/* Slate 300 */
--text-dim-dark: #64748b;     /* Slate 500 */
--border-dark: #334155;       /* Slate 700 */
```

## Typography

### Font Stack
```css
--font-body: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
--font-mono: 'IBM Plex Mono', 'Fira Code', 'Consolas', monospace;
```

### Font Sizes
```css
--text-xs: 0.75rem;    /* 12px - metadata, timestamps */
--text-sm: 0.875rem;   /* 14px - body, table cells */
--text-base: 1rem;     /* 16px - primary content */
--text-lg: 1.125rem;   /* 18px - section headers */
--text-xl: 1.25rem;    /* 20px - page headers */
--text-2xl: 1.5rem;    /* 24px - hero numbers */
```

### Usage
- **Body text**: IBM Plex Sans, 14-16px
- **Code/payloads**: IBM Plex Mono, 13-14px
- **KPI numbers**: IBM Plex Mono, 24-32px (monospace for alignment)
- **Section labels**: IBM Plex Sans, uppercase, letter-spacing 0.05em

## Visual Hierarchy (Depth Tiers)

### Hero (Elevated)
Used for: Executive summary, grade card, key metrics
```css
.depth-hero {
    background: var(--bg-primary);
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
    border-radius: 0.5rem;
    padding: 1.5rem;
}
```

### Default (Standard)
Used for: Finding cards, tables, general content
```css
.depth-default {
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.375rem;
    padding: 1rem;
}
```

### Recessed (Subdued)
Used for: Metadata, timestamps, secondary info
```css
.depth-recessed {
    background: var(--bg-recessed);
    border-radius: 0.25rem;
    padding: 0.5rem 0.75rem;
    color: var(--text-secondary);
}
```

## Section Labels

Replace emoji headers with professional dot labels:

```css
.section-label {
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-dim);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.section-label::before {
    content: '';
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--accent-primary);
}
```

---

## Forbidden Patterns (AI Slop)

These patterns signal "AI-generated template" and are **explicitly banned**:

### Typography
- ❌ Inter as primary body font (most overused AI default)
- ❌ Roboto, Arial, Helvetica as primary fonts
- ❌ system-ui alone without named fallback

### Colors
- ❌ `#8b5cf6` (violet-500) — Tailwind purple default
- ❌ `#7c3aed` (violet-600) — Tailwind purple default
- ❌ `#a78bfa` (violet-400) — Tailwind purple default
- ❌ `#6366f1` (indigo-500) — Tailwind indigo default
- ❌ `#4f46e5` (indigo-600) — Tailwind indigo default
- ❌ `#d946ef` (fuchsia-500) — Neon pink
- ❌ Cyan + magenta + pink neon gradients

### Visual Effects
- ❌ `background-clip: text` gradient text on headings
- ❌ Animated glowing box-shadows (`@keyframes glow`)
- ❌ Three-dot window chrome on code blocks
- ❌ Emoji icons in section headers (🚨, ⚠️, ✅, 📋)

### Layout
- ❌ All cards styled identically with no visual hierarchy
- ❌ Excessive rounded corners (> 1rem)
- ❌ Gratuitous animations on every element

---

## Component Patterns

### KPI Card
```html
<div class="kpi-card depth-hero">
    <span class="section-label">Total Bypasses</span>
    <span class="kpi-value">142</span>
</div>
```

### Finding Table Header
```html
<th class="table-header">
    Severity
</th>
```
```css
.table-header {
    font-family: var(--font-body);
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--text-secondary);
    background: var(--bg-recessed);
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 2px solid var(--border);
}
```

### Severity Badge
```css
.severity-badge {
    display: inline-flex;
    align-items: center;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-size: var(--text-xs);
    font-weight: 600;
    text-transform: uppercase;
}

.severity-critical { background: #fef2f2; color: #dc2626; }
.severity-high { background: #fff7ed; color: #ea580c; }
.severity-medium { background: #fefce8; color: #ca8a04; }
.severity-low { background: #f0fdf4; color: #16a34a; }
```

---

## Print Styles

```css
@media print {
    .depth-hero,
    .depth-default {
        box-shadow: none;
        border: 1px solid #e2e8f0;
    }
    
    /* Force light theme for printing */
    :root {
        --bg-primary: #ffffff;
        --text-primary: #0f172a;
    }
    
    /* Hide interactive elements */
    .theme-toggle,
    .export-button,
    .collapsible-trigger {
        display: none;
    }
    
    /* Prevent page breaks inside cards */
    .finding-card {
        break-inside: avoid;
    }
}
```

---

## Accessibility

### Motion
```css
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
}
```

### Focus States
```css
:focus-visible {
    outline: 2px solid var(--accent-primary);
    outline-offset: 2px;
}
```

### Color Contrast
All text must meet WCAG AA contrast ratios:
- Normal text: 4.5:1 minimum
- Large text (18px+): 3:1 minimum

---

## Implementation Checklist

When implementing or reviewing HTML output:

- [ ] Uses IBM Plex Sans (body) + IBM Plex Mono (code)
- [ ] Uses teal accent (#0d9488), NOT purple/violet/indigo
- [ ] No emoji in section headers
- [ ] No gradient text
- [ ] No animated glow effects
- [ ] Visual hierarchy with depth tiers
- [ ] Print styles hide interactive elements
- [ ] Respects prefers-reduced-motion
- [ ] Respects prefers-color-scheme for auto theme

---

## PDF Output

The PDF writer uses gofpdf which has limited font support. Custom fonts require embedding TTF files.

### Current Approach

PDF reports use Helvetica (built-in) for compatibility:
- Body: Helvetica (closest built-in to IBM Plex Sans feel)
- Mono: Courier (built-in monospace)
- Colors: Same severity palette as HTML (#dc2626, #ea580c, #ca8a04, #16a34a, #2563eb)

### Future Enhancement

To embed IBM Plex fonts:
1. Download TTF files from Google Fonts
2. Use gofpdf's `AddUTF8Font` method
3. Bundle fonts in `pkg/output/writers/fonts/`

This is not a priority since HTML is the primary output format.
