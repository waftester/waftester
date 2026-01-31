package override

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionConstants(t *testing.T) {
	assert.Equal(t, Action("skip"), ActionSkip)
	assert.Equal(t, Action("modify"), ActionModify)
	assert.Equal(t, Action("enable"), ActionEnable)
	assert.Equal(t, Action("disable"), ActionDisable)
	assert.Equal(t, Action("priority"), ActionPriority)
}

func TestOverrideIsExpired(t *testing.T) {
	t.Run("no expiry", func(t *testing.T) {
		o := &Override{TestID: "test-1"}
		assert.False(t, o.IsExpired())
	})

	t.Run("future expiry", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		o := &Override{TestID: "test-1", ExpiresAt: &future}
		assert.False(t, o.IsExpired())
	})

	t.Run("past expiry", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		o := &Override{TestID: "test-1", ExpiresAt: &past}
		assert.True(t, o.IsExpired())
	})
}

func TestConditionMatches(t *testing.T) {
	tests := []struct {
		name       string
		condition  Condition
		fieldValue string
		expected   bool
	}{
		{"eq matches", Condition{Operator: "eq", Value: "test"}, "test", true},
		{"eq no match", Condition{Operator: "eq", Value: "test"}, "other", false},
		{"== matches", Condition{Operator: "==", Value: "test"}, "test", true},
		{"equals matches", Condition{Operator: "equals", Value: "test"}, "test", true},
		{"ne matches", Condition{Operator: "ne", Value: "test"}, "other", true},
		{"ne no match", Condition{Operator: "ne", Value: "test"}, "test", false},
		{"!= matches", Condition{Operator: "!=", Value: "test"}, "other", true},
		{"not_equals matches", Condition{Operator: "not_equals", Value: "test"}, "other", true},
		{"contains matches", Condition{Operator: "contains", Value: "test"}, "this is a test", true},
		{"contains no match", Condition{Operator: "contains", Value: "test"}, "hello world", false},
		{"prefix matches", Condition{Operator: "prefix", Value: "hello"}, "hello world", true},
		{"prefix no match", Condition{Operator: "prefix", Value: "world"}, "hello world", false},
		{"starts_with matches", Condition{Operator: "starts_with", Value: "hello"}, "hello world", true},
		{"suffix matches", Condition{Operator: "suffix", Value: "world"}, "hello world", true},
		{"suffix no match", Condition{Operator: "suffix", Value: "hello"}, "hello world", false},
		{"ends_with matches", Condition{Operator: "ends_with", Value: "world"}, "hello world", true},
		{"unknown operator", Condition{Operator: "unknown", Value: "test"}, "test", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.condition.Matches(tc.fieldValue)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.AllowExpired)
}

func TestNewManager(t *testing.T) {
	t.Run("with nil config", func(t *testing.T) {
		m := NewManager(nil)
		require.NotNil(t, m)
		assert.NotNil(t, m.overrides)
		assert.False(t, m.config.AllowExpired)
	})

	t.Run("with custom config", func(t *testing.T) {
		cfg := &Config{AllowExpired: true}
		m := NewManager(cfg)
		require.NotNil(t, m)
		assert.True(t, m.config.AllowExpired)
	})
}

func TestManagerAdd(t *testing.T) {
	m := NewManager(nil)
	o := &Override{TestID: "test-1", Action: ActionSkip, Reason: "Test"}

	m.Add(o)

	result, ok := m.Get("test-1")
	assert.True(t, ok)
	assert.Equal(t, o, result)
}

func TestManagerRemove(t *testing.T) {
	m := NewManager(nil)
	o := &Override{TestID: "test-1", Action: ActionSkip}
	m.Add(o)

	t.Run("remove existing", func(t *testing.T) {
		removed := m.Remove("test-1")
		assert.True(t, removed)
		_, ok := m.Get("test-1")
		assert.False(t, ok)
	})

	t.Run("remove non-existing", func(t *testing.T) {
		removed := m.Remove("nonexistent")
		assert.False(t, removed)
	})
}

func TestManagerGet(t *testing.T) {
	m := NewManager(nil)
	o := &Override{TestID: "test-1", Action: ActionSkip}
	m.Add(o)

	t.Run("existing", func(t *testing.T) {
		result, ok := m.Get("test-1")
		assert.True(t, ok)
		assert.Equal(t, "test-1", result.TestID)
	})

	t.Run("non-existing", func(t *testing.T) {
		result, ok := m.Get("nonexistent")
		assert.False(t, ok)
		assert.Nil(t, result)
	})
}

func TestManagerList(t *testing.T) {
	m := NewManager(nil)

	t.Run("empty", func(t *testing.T) {
		list := m.List()
		assert.Empty(t, list)
	})

	t.Run("with items", func(t *testing.T) {
		m.Add(&Override{TestID: "test-1"})
		m.Add(&Override{TestID: "test-2"})
		list := m.List()
		assert.Len(t, list, 2)
	})
}

func TestManagerListActive(t *testing.T) {
	m := NewManager(nil)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	m.Add(&Override{TestID: "active-1"})
	m.Add(&Override{TestID: "active-2", ExpiresAt: &future})
	m.Add(&Override{TestID: "expired", ExpiresAt: &past})

	active := m.ListActive()
	assert.Len(t, active, 2)

	ids := make([]string, len(active))
	for i, o := range active {
		ids[i] = o.TestID
	}
	assert.Contains(t, ids, "active-1")
	assert.Contains(t, ids, "active-2")
	assert.NotContains(t, ids, "expired")
}

func TestManagerApply(t *testing.T) {
	t.Run("no override", func(t *testing.T) {
		m := NewManager(nil)
		test := &Test{ID: "test-1"}
		result := m.Apply(test)
		assert.False(t, result.Applied)
	})

	t.Run("skip action", func(t *testing.T) {
		m := NewManager(nil)
		m.Add(&Override{TestID: "test-1", Action: ActionSkip})
		test := &Test{ID: "test-1"}
		result := m.Apply(test)
		assert.True(t, result.Applied)
		assert.True(t, result.SkipTest)
		assert.Equal(t, ActionSkip, result.Action)
	})

	t.Run("disable action", func(t *testing.T) {
		m := NewManager(nil)
		m.Add(&Override{TestID: "test-1", Action: ActionDisable})
		test := &Test{ID: "test-1"}
		result := m.Apply(test)
		assert.True(t, result.Applied)
		assert.True(t, result.SkipTest)
	})

	t.Run("enable action", func(t *testing.T) {
		m := NewManager(nil)
		m.Add(&Override{TestID: "test-1", Action: ActionEnable})
		test := &Test{ID: "test-1"}
		result := m.Apply(test)
		assert.True(t, result.Applied)
		assert.False(t, result.SkipTest)
	})

	t.Run("modify action", func(t *testing.T) {
		m := NewManager(nil)
		expectBlock := true
		m.Add(&Override{
			TestID: "test-1",
			Action: ActionModify,
			Replacement: &Replacement{
				Payload:     "new-payload",
				ExpectBlock: &expectBlock,
				Method:      "POST",
				Headers:     map[string]string{"X-Custom": "value"},
			},
		})
		test := &Test{ID: "test-1", Payload: "old", Method: "GET"}
		result := m.Apply(test)
		assert.True(t, result.Applied)
		require.NotNil(t, result.Modified)
		assert.Equal(t, "new-payload", result.Modified.Payload)
		assert.Equal(t, "POST", result.Modified.Method)
		assert.True(t, result.Modified.ExpectBlock)
		assert.Equal(t, "value", result.Modified.Headers["X-Custom"])
	})

	t.Run("expired override not applied", func(t *testing.T) {
		m := NewManager(nil)
		past := time.Now().Add(-time.Hour)
		m.Add(&Override{TestID: "test-1", Action: ActionSkip, ExpiresAt: &past})
		test := &Test{ID: "test-1"}
		result := m.Apply(test)
		assert.False(t, result.Applied)
	})

	t.Run("expired override applied with AllowExpired", func(t *testing.T) {
		m := NewManager(&Config{AllowExpired: true})
		past := time.Now().Add(-time.Hour)
		m.Add(&Override{TestID: "test-1", Action: ActionSkip, ExpiresAt: &past})
		test := &Test{ID: "test-1"}
		result := m.Apply(test)
		assert.True(t, result.Applied)
	})

	t.Run("condition matches", func(t *testing.T) {
		m := NewManager(nil)
		m.Add(&Override{
			TestID: "test-1",
			Action: ActionSkip,
			Conditions: []Condition{
				{Field: "category", Operator: "eq", Value: "sqli"},
			},
		})
		test := &Test{ID: "test-1", Category: "sqli"}
		result := m.Apply(test)
		assert.True(t, result.Applied)
	})

	t.Run("condition not matches", func(t *testing.T) {
		m := NewManager(nil)
		m.Add(&Override{
			TestID: "test-1",
			Action: ActionSkip,
			Conditions: []Condition{
				{Field: "category", Operator: "eq", Value: "xss"},
			},
		})
		test := &Test{ID: "test-1", Category: "sqli"}
		result := m.Apply(test)
		assert.False(t, result.Applied)
	})

	t.Run("multiple conditions all must match", func(t *testing.T) {
		m := NewManager(nil)
		m.Add(&Override{
			TestID: "test-1",
			Action: ActionSkip,
			Conditions: []Condition{
				{Field: "category", Operator: "eq", Value: "sqli"},
				{Field: "method", Operator: "eq", Value: "POST"},
			},
		})

		t.Run("both match", func(t *testing.T) {
			test := &Test{ID: "test-1", Category: "sqli", Method: "POST"}
			result := m.Apply(test)
			assert.True(t, result.Applied)
		})

		t.Run("one matches", func(t *testing.T) {
			test := &Test{ID: "test-1", Category: "sqli", Method: "GET"}
			result := m.Apply(test)
			assert.False(t, result.Applied)
		})
	})
}

func TestManagerCount(t *testing.T) {
	m := NewManager(nil)
	assert.Equal(t, 0, m.Count())

	m.Add(&Override{TestID: "test-1"})
	assert.Equal(t, 1, m.Count())

	m.Add(&Override{TestID: "test-2"})
	assert.Equal(t, 2, m.Count())
}

func TestManagerClear(t *testing.T) {
	m := NewManager(nil)
	m.Add(&Override{TestID: "test-1"})
	m.Add(&Override{TestID: "test-2"})
	assert.Equal(t, 2, m.Count())

	m.Clear()
	assert.Equal(t, 0, m.Count())
}

func TestManagerSaveLoadFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "overrides.json")

	m1 := NewManager(nil)
	m1.Add(&Override{
		TestID:    "test-1",
		Action:    ActionSkip,
		Reason:    "Test reason",
		CreatedAt: time.Now(),
	})
	m1.Add(&Override{
		TestID:    "test-2",
		Action:    ActionModify,
		Reason:    "Another reason",
		CreatedAt: time.Now(),
	})

	err := m1.SaveToFile(path)
	require.NoError(t, err)

	m2 := NewManager(nil)
	err = m2.LoadFromFile(path)
	require.NoError(t, err)

	assert.Equal(t, 2, m2.Count())
	o1, ok := m2.Get("test-1")
	assert.True(t, ok)
	assert.Equal(t, ActionSkip, o1.Action)
	assert.Equal(t, "Test reason", o1.Reason)
}

func TestManagerLoadFromFileNotFound(t *testing.T) {
	m := NewManager(nil)
	err := m.LoadFromFile("/nonexistent/path/file.json")
	assert.Error(t, err)
}

func TestManagerSaveToFileCreatesDir(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "nested", "overrides.json")

	m := NewManager(nil)
	m.Add(&Override{TestID: "test-1", Action: ActionSkip})

	err := m.SaveToFile(path)
	require.NoError(t, err)

	_, err = os.Stat(path)
	assert.NoError(t, err)
}

func TestTestStruct(t *testing.T) {
	test := Test{
		ID:          "test-1",
		RuleID:      "942100",
		Category:    "sqli",
		Payload:     "' OR '1'='1",
		ExpectBlock: true,
		Method:      "POST",
		Headers:     map[string]string{"Content-Type": "application/json"},
		Tags:        []string{"owasp", "sqli"},
	}

	assert.Equal(t, "test-1", test.ID)
	assert.Equal(t, "942100", test.RuleID)
	assert.Equal(t, "sqli", test.Category)
	assert.True(t, test.ExpectBlock)
}

func TestResultStruct(t *testing.T) {
	o := &Override{TestID: "test-1", Action: ActionSkip}
	result := Result{
		Applied:  true,
		Override: o,
		Action:   ActionSkip,
		SkipTest: true,
	}

	assert.True(t, result.Applied)
	assert.Equal(t, o, result.Override)
	assert.True(t, result.SkipTest)
}

func TestReplacementStruct(t *testing.T) {
	expectBlock := false
	r := Replacement{
		Payload:     "new-payload",
		ExpectBlock: &expectBlock,
		Headers:     map[string]string{"X-Test": "value"},
		Method:      "PUT",
	}

	assert.Equal(t, "new-payload", r.Payload)
	assert.False(t, *r.ExpectBlock)
	assert.Equal(t, "PUT", r.Method)
}

func TestOverrideJSON(t *testing.T) {
	expires := time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
	o := Override{
		TestID:    "test-1",
		RuleID:    "942100",
		Action:    ActionSkip,
		Reason:    "Known false positive",
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: &expires,
		CreatedBy: "user@example.com",
		Metadata:  map[string]string{"ticket": "JIRA-123"},
	}

	data, err := json.Marshal(o)
	require.NoError(t, err)

	var o2 Override
	err = json.Unmarshal(data, &o2)
	require.NoError(t, err)

	assert.Equal(t, o.TestID, o2.TestID)
	assert.Equal(t, o.Action, o2.Action)
	assert.Equal(t, o.Reason, o2.Reason)
	assert.Equal(t, "JIRA-123", o2.Metadata["ticket"])
}

func TestConditionFields(t *testing.T) {
	m := NewManager(nil)
	m.Add(&Override{
		TestID: "test-1",
		Action: ActionSkip,
		Conditions: []Condition{
			{Field: "rule_id", Operator: "eq", Value: "942100"},
		},
	})

	t.Run("rule_id field", func(t *testing.T) {
		test := &Test{ID: "test-1", RuleID: "942100"}
		result := m.Apply(test)
		assert.True(t, result.Applied)
	})

	t.Run("rule_id no match", func(t *testing.T) {
		test := &Test{ID: "test-1", RuleID: "941100"}
		result := m.Apply(test)
		assert.False(t, result.Applied)
	})
}

func TestContainsHelper(t *testing.T) {
	assert.True(t, contains("hello world", "world"))
	assert.True(t, contains("test", "test"))
	assert.False(t, contains("hello", "world"))
	assert.False(t, contains("", "test"))
	assert.True(t, contains("test", ""))
}
