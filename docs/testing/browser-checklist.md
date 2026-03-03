# HTML Report Browser Testing Checklist

Manual verification checklist for HTML report output across browsers.

## Test Environment Setup

1. Generate test report:
   ```bash
   ./waftester scan https://httpbin.org/anything --output html:test-report.html
   ```

2. Open `test-report.html` in each browser below

## Browser Matrix

| Browser | Version | Fonts Load | Layout OK | Dark Mode | Print OK | Console Clean |
|---------|---------|------------|-----------|-----------|----------|---------------|
| Chrome  | 120+    | ☐          | ☐         | ☐         | ☐        | ☐             |
| Firefox | 115+    | ☐          | ☐         | ☐         | ☐        | ☐             |
| Edge    | 120+    | ☐          | ☐         | ☐         | ☐        | ☐             |
| Safari  | 16+     | ☐          | ☐         | ☐         | ☐        | ☐             |

## Verification Steps

### 1. Fonts Load
- Open DevTools Network tab
- Filter by "Font"
- Verify IBM Plex Sans and IBM Plex Mono load (200 OK)
- No 404 errors for font files

### 2. Layout OK
- Executive Summary section visible with teal accent border
- Findings table renders with proper columns
- Risk chart SVG displays correctly
- No horizontal scrolling on desktop (>1024px)
- Mobile layout works (<768px)

### 3. Dark Mode
- Toggle system dark mode preference OR
- If theme toggle exists, use it
- Text remains readable (sufficient contrast)
- Background colors switch to dark slate palette
- No pure white (#ffffff) elements in dark mode

### 4. Print Preview
- Press Ctrl+P (Cmd+P on Mac)
- Interactive elements hidden (theme toggle, buttons)
- Page breaks don't split finding cards
- Colors print correctly
- No excessive blank space

### 5. Console Clean
- Open DevTools Console
- No JavaScript errors (red)
- No CSS warnings about missing resources
- No accessibility warnings

## Accessibility Quick Check

- [ ] Tab through interactive elements (focus ring visible)
- [ ] Screen reader announces SVG chart title
- [ ] Links have visible focus states
- [ ] No content requires hover to access

## Known Limitations

- Safari <14.1: May have minor CSS compatibility issues with newer features
- Firefox <104: rgba() syntax required (we use rgba, not rgb with /)
- IE11: Not supported (EOL)

## Reporting Issues

If a browser fails any check:
1. Note browser version
2. Screenshot the issue
3. Check DevTools for specific error
4. File issue with `browser-compat` label
