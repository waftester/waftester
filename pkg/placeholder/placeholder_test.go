package placeholder

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "{{", cfg.Prefix)
	assert.Equal(t, "}}", cfg.Suffix)
	assert.Equal(t, "PAYLOAD", cfg.PayloadKey)
}

func TestNewEngine(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		e := NewEngine(nil)
		require.NotNil(t, e)
		assert.Equal(t, "{{", e.config.Prefix)
	})

	t.Run("with custom config", func(t *testing.T) {
		cfg := &Config{Prefix: "${", Suffix: "}", PayloadKey: "INPUT"}
		e := NewEngine(cfg)
		require.NotNil(t, e)
		assert.Equal(t, "${", e.config.Prefix)
		assert.Equal(t, "INPUT", e.config.PayloadKey)
	})
}

func TestEngineRegisterBuiltins(t *testing.T) {
	e := NewEngine(nil)

	builtinNames := []string{
		"PAYLOAD", "TARGET", "HOST", "PORT", "PATH", "METHOD",
		"RANDOM", "TIMESTAMP", "USER", "PASS", "TOKEN", "SESSION",
		"COOKIE", "HEADER", "BODY", "QUERY", "PARAM", "VALUE",
	}

	for _, name := range builtinNames {
		p, ok := e.Get(name)
		assert.True(t, ok, "builtin %s should exist", name)
		assert.NotNil(t, p)
	}
}

func TestEngineRegister(t *testing.T) {
	e := NewEngine(nil)

	custom := &Placeholder{
		Name:        "CUSTOM",
		Description: "Custom placeholder",
		Required:    true,
	}
	e.Register(custom)

	p, ok := e.Get("CUSTOM")
	assert.True(t, ok)
	assert.Equal(t, "Custom placeholder", p.Description)
	assert.True(t, p.Required)
}

func TestEngineGet(t *testing.T) {
	e := NewEngine(nil)

	t.Run("existing placeholder", func(t *testing.T) {
		p, ok := e.Get("PAYLOAD")
		assert.True(t, ok)
		assert.Equal(t, "PAYLOAD", p.Name)
	})

	t.Run("non-existing placeholder", func(t *testing.T) {
		p, ok := e.Get("NONEXISTENT")
		assert.False(t, ok)
		assert.Nil(t, p)
	})
}

func TestEngineList(t *testing.T) {
	e := NewEngine(nil)
	list := e.List()

	assert.NotEmpty(t, list)
	assert.GreaterOrEqual(t, len(list), 10) // At least 10 builtins
}

func TestEngineProcess(t *testing.T) {
	e := NewEngine(nil)

	t.Run("replace single placeholder", func(t *testing.T) {
		template := "Hello {{NAME}}"
		values := []Value{{Name: "NAME", Value: "World"}}
		result := e.Process(template, values)
		assert.Equal(t, "Hello World", result)
	})

	t.Run("replace multiple placeholders", func(t *testing.T) {
		template := "{{METHOD}} {{PATH}} HTTP/1.1"
		values := []Value{
			{Name: "METHOD", Value: "POST"},
			{Name: "PATH", Value: "/api/test"},
		}
		result := e.Process(template, values)
		assert.Equal(t, "POST /api/test HTTP/1.1", result)
	})

	t.Run("use default value", func(t *testing.T) {
		template := "Port: {{PORT}}"
		result := e.Process(template, nil)
		assert.Equal(t, "Port: 80", result) // PORT has default 80
	})

	t.Run("unmatched placeholder unchanged", func(t *testing.T) {
		template := "Unknown: {{UNKNOWN}}"
		result := e.Process(template, nil)
		assert.Equal(t, "Unknown: {{UNKNOWN}}", result)
	})

	t.Run("empty values", func(t *testing.T) {
		template := "No placeholders here"
		result := e.Process(template, nil)
		assert.Equal(t, "No placeholders here", result)
	})
}

func TestEngineInject(t *testing.T) {
	e := NewEngine(nil)

	t.Run("inject payload", func(t *testing.T) {
		template := "SELECT * FROM users WHERE id={{PAYLOAD}}"
		result := e.Inject(template, "1 OR 1=1")
		assert.Equal(t, "SELECT * FROM users WHERE id=1 OR 1=1", result)
	})

	t.Run("inject XSS payload", func(t *testing.T) {
		template := "<input value=\"{{PAYLOAD}}\">"
		result := e.Inject(template, "<script>alert(1)</script>")
		assert.Equal(t, "<input value=\"<script>alert(1)</script>\">", result)
	})

	t.Run("no payload placeholder", func(t *testing.T) {
		template := "Hello World"
		result := e.Inject(template, "payload")
		assert.Equal(t, "Hello World", result)
	})
}

func TestEngineExtract(t *testing.T) {
	e := NewEngine(nil)

	t.Run("extract single", func(t *testing.T) {
		names := e.Extract("Hello {{NAME}}")
		assert.Equal(t, []string{"NAME"}, names)
	})

	t.Run("extract multiple", func(t *testing.T) {
		names := e.Extract("{{METHOD}} {{PATH}} {{VERSION}}")
		assert.Len(t, names, 3)
		assert.Contains(t, names, "METHOD")
		assert.Contains(t, names, "PATH")
		assert.Contains(t, names, "VERSION")
	})

	t.Run("deduplicate", func(t *testing.T) {
		names := e.Extract("{{NAME}} and {{NAME}} again")
		assert.Len(t, names, 1)
		assert.Equal(t, "NAME", names[0])
	})

	t.Run("no placeholders", func(t *testing.T) {
		names := e.Extract("No placeholders")
		assert.Empty(t, names)
	})
}

func TestEngineValidate(t *testing.T) {
	e := NewEngine(nil)

	t.Run("all required filled", func(t *testing.T) {
		template := "{{PAYLOAD}} to {{TARGET}}"
		values := []Value{
			{Name: "PAYLOAD", Value: "test"},
			{Name: "TARGET", Value: "http://example.com"},
		}
		missing := e.Validate(template, values)
		assert.Empty(t, missing)
	})

	t.Run("missing required", func(t *testing.T) {
		template := "{{PAYLOAD}} to {{TARGET}}"
		values := []Value{
			{Name: "PAYLOAD", Value: "test"},
		}
		missing := e.Validate(template, values)
		assert.Contains(t, missing, "TARGET")
	})

	t.Run("optional not required", func(t *testing.T) {
		template := "{{PORT}}" // PORT has default, not required
		missing := e.Validate(template, nil)
		assert.Empty(t, missing)
	})
}

func TestEngineHasPlaceholders(t *testing.T) {
	e := NewEngine(nil)

	assert.True(t, e.HasPlaceholders("{{PAYLOAD}}"))
	assert.True(t, e.HasPlaceholders("Hello {{NAME}}"))
	assert.False(t, e.HasPlaceholders("No placeholders"))
	assert.False(t, e.HasPlaceholders("{INVALID}"))
}

func TestEngineCount(t *testing.T) {
	e := NewEngine(nil)

	assert.Equal(t, 0, e.Count("No placeholders"))
	assert.Equal(t, 1, e.Count("{{ONE}}"))
	assert.Equal(t, 3, e.Count("{{A}} {{B}} {{C}}"))
	assert.Equal(t, 2, e.Count("{{SAME}} {{SAME}}")) // Counts occurrences, not unique
}

func TestNewBuilder(t *testing.T) {
	t.Run("with nil engine", func(t *testing.T) {
		b := NewBuilder(nil)
		require.NotNil(t, b)
		require.NotNil(t, b.engine)
	})

	t.Run("with engine", func(t *testing.T) {
		e := NewEngine(nil)
		b := NewBuilder(e)
		require.NotNil(t, b)
		assert.Equal(t, e, b.engine)
	})
}

func TestBuilderText(t *testing.T) {
	b := NewBuilder(nil)
	result := b.Text("Hello").Build()
	assert.Equal(t, "Hello", result)
}

func TestBuilderPlaceholder(t *testing.T) {
	b := NewBuilder(nil)
	result := b.Placeholder("NAME").Build()
	assert.Equal(t, "{{NAME}}", result)
}

func TestBuilderPayload(t *testing.T) {
	b := NewBuilder(nil)
	result := b.Payload().Build()
	assert.Equal(t, "{{PAYLOAD}}", result)
}

func TestBuilderChaining(t *testing.T) {
	b := NewBuilder(nil)
	result := b.Text("SELECT * FROM users WHERE id=").Payload().Text(" --").Build()
	assert.Equal(t, "SELECT * FROM users WHERE id={{PAYLOAD}} --", result)
}

func TestBuilderReset(t *testing.T) {
	b := NewBuilder(nil)
	b.Text("First").Build()
	b.Reset()
	result := b.Text("Second").Build()
	assert.Equal(t, "Second", result)
}

func TestBuilderComplexTemplate(t *testing.T) {
	b := NewBuilder(nil)
	template := b.
		Text("POST ").
		Placeholder("PATH").
		Text(" HTTP/1.1\r\nHost: ").
		Placeholder("HOST").
		Text("\r\n\r\n").
		Payload().
		Build()

	assert.Equal(t, "POST {{PATH}} HTTP/1.1\r\nHost: {{HOST}}\r\n\r\n{{PAYLOAD}}", template)
}

func TestCustomConfig(t *testing.T) {
	cfg := &Config{
		Prefix:     "${",
		Suffix:     "}",
		PayloadKey: "INPUT",
	}
	e := NewEngine(cfg)

	t.Run("extract with custom delimiters", func(t *testing.T) {
		names := e.Extract("${NAME} and ${VALUE}")
		assert.Contains(t, names, "NAME")
		assert.Contains(t, names, "VALUE")
	})

	t.Run("process with custom delimiters", func(t *testing.T) {
		result := e.Process("Hello ${NAME}", []Value{{Name: "NAME", Value: "World"}})
		assert.Equal(t, "Hello World", result)
	})

	t.Run("inject with custom payload key", func(t *testing.T) {
		result := e.Inject("Value: ${INPUT}", "test")
		assert.Equal(t, "Value: test", result)
	})
}

func TestValueStruct(t *testing.T) {
	v := Value{
		Name:    "TEST",
		Value:   "value",
		Default: "default",
	}
	assert.Equal(t, "TEST", v.Name)
	assert.Equal(t, "value", v.Value)
	assert.Equal(t, "default", v.Default)
}

func TestPlaceholderStruct(t *testing.T) {
	p := Placeholder{
		Name:        "CUSTOM",
		Pattern:     "[a-z]+",
		Description: "A custom placeholder",
		Default:     "default",
		Required:    true,
	}
	assert.Equal(t, "CUSTOM", p.Name)
	assert.Equal(t, "[a-z]+", p.Pattern)
	assert.True(t, p.Required)
}
