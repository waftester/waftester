package tampers

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScriptTamper_Transform(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "test-tamper.tengo")
	err := os.WriteFile(scriptPath, []byte(`
text := import("text")
name := "test-space-to-comment"
description := "Replaces spaces with /**/ for SQL bypass"
category := "sql"
priority := 50

transform := func(payload) {
    return text.replace(payload, " ", "/**/", -1)
}
`), 0644)
	require.NoError(t, err)

	tamper, err := LoadScriptTamper(scriptPath)
	require.NoError(t, err)
	assert.Equal(t, "test-space-to-comment", tamper.Name())
	assert.Equal(t, "Replaces spaces with /**/ for SQL bypass", tamper.Description())
	assert.Equal(t, Category("sql"), tamper.Category())
	assert.Equal(t, Priority(50), tamper.Priority())
	assert.Equal(t, "SELECT/**/1/**/FROM/**/users", tamper.Transform("SELECT 1 FROM users"))
}

func TestScriptTamper_DefaultCategory(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "minimal.tengo")
	err := os.WriteFile(scriptPath, []byte(`
name := "minimal"
description := "minimal tamper"
transform := func(payload) { return payload + "!" }
`), 0644)
	require.NoError(t, err)

	tamper, err := LoadScriptTamper(scriptPath)
	require.NoError(t, err)
	assert.Equal(t, Category("custom"), tamper.Category())
	assert.Equal(t, PriorityNormal, tamper.Priority())
	assert.Equal(t, "hello!", tamper.Transform("hello"))
}

func TestScriptTamper_MissingName(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "bad.tengo")
	err := os.WriteFile(scriptPath, []byte(`
description := "no name"
transform := func(p) { return p }
`), 0644)
	require.NoError(t, err)

	_, err = LoadScriptTamper(scriptPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing 'name'")
}

func TestScriptTamper_MissingTransform(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "bad.tengo")
	err := os.WriteFile(scriptPath, []byte(`
name := "bad"
description := "no transform"
`), 0644)
	require.NoError(t, err)

	_, err = LoadScriptTamper(scriptPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing 'transform'")
}

func TestScriptTamper_Sandbox(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "evil.tengo")
	err := os.WriteFile(scriptPath, []byte(`
os := import("os")
name := "evil"
description := "tries to read files"
transform := func(p) { return p }
`), 0644)
	require.NoError(t, err)

	_, err = LoadScriptTamper(scriptPath)
	assert.Error(t, err) // os module not in safe modules
}

func TestScriptTamper_TransformError(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "runtime-err.tengo")
	err := os.WriteFile(scriptPath, []byte(`
name := "runtime-err"
description := "crashes at runtime"
transform := func(payload) {
    x := 1 / 0
    return x
}
`), 0644)
	require.NoError(t, err)

	tamper, err := LoadScriptTamper(scriptPath)
	require.NoError(t, err)

	// Should return original payload on runtime error
	result := tamper.Transform("test")
	assert.Equal(t, "test", result)
}

func TestScriptTamper_TransformRequest(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "test.tengo")
	err := os.WriteFile(scriptPath, []byte(`
name := "test"
description := "test"
transform := func(p) { return p }
`), 0644)
	require.NoError(t, err)

	tamper, err := LoadScriptTamper(scriptPath)
	require.NoError(t, err)

	// Script tampers don't modify requests
	assert.Nil(t, tamper.TransformRequest(nil))
}

func TestLoadScriptDir(t *testing.T) {
	dir := t.TempDir()

	// Create 2 valid scripts
	for i := 0; i < 2; i++ {
		script := fmt.Sprintf(`
name := "tamper%d"
description := "test tamper %d"
transform := func(p) { return p + "%d" }
`, i, i, i)
		err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("t%d.tengo", i)), []byte(script), 0644)
		require.NoError(t, err)
	}

	// Create 1 broken script
	err := os.WriteFile(filepath.Join(dir, "broken.tengo"), []byte(`broken syntax {{{{`), 0644)
	require.NoError(t, err)

	// Create 1 non-tengo file (should be ignored)
	err = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a script"), 0644)
	require.NoError(t, err)

	tampers, errs := LoadScriptDir(dir)
	assert.Len(t, tampers, 2)
	assert.Len(t, errs, 1) // broken.tengo
}

func TestLoadScriptDir_NonexistentDir(t *testing.T) {
	tampers, errs := LoadScriptDir("/nonexistent/path")
	assert.Nil(t, tampers)
	assert.Len(t, errs, 1)
}

func TestLoadScriptDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	tampers, errs := LoadScriptDir(dir)
	assert.Nil(t, tampers)
	assert.Nil(t, errs)
}

func TestScriptTamper_RejectsOversizedFile(t *testing.T) {
	// Scripts larger than 1MB must be rejected to prevent resource exhaustion.
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.tengo")

	// Create a 1.1MB file — just over the limit.
	data := make([]byte, 1100*1024)
	for i := range data {
		data[i] = '/'
	}
	require.NoError(t, os.WriteFile(path, data, 0644))

	_, err := LoadScriptTamper(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestScriptTamper_AcceptsFileUnderLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "small.tengo")

	// Valid small script (well under 1MB).
	script := []byte(`
name := "small"
description := "test"
transform := func(p) { return p }
`)
	require.NoError(t, os.WriteFile(path, script, 0644))

	tamper, err := LoadScriptTamper(path)
	require.NoError(t, err)
	assert.Equal(t, "small", tamper.Name())
}
