# Templates

Nuclei and custom templates for WAF testing.

## Report Template Configs

Pre-built report template configurations are available in `pkg/report/templates/configs/`:

| Template | Description | Use Case |
|----------|-------------|----------|
| `minimal.yaml` | Condensed report with essential findings only | Quick assessments, executive overviews |
| `enterprise.yaml` | Full-featured report with all metrics | Detailed security audits, compliance |

### Usage

```bash
# Use minimal template for a quick summary
waf-tester scan https://example.com --html report.html --template-config pkg/report/templates/configs/minimal.yaml

# Use enterprise template for detailed audit
waf-tester scan https://example.com --html report.html --template-config pkg/report/templates/configs/enterprise.yaml
```

### Custom Templates

You can create your own template config by copying one of the presets and modifying it. See the YAML files for all available options including:

- **Branding**: Company name, logo, colors
- **Layout**: Theme (light/dark/auto), page width, compact mode
- **Sections**: Enable/disable specific report sections
- **Styling**: Fonts, colors, border radius
- **Charts**: Color palette, animation settings
