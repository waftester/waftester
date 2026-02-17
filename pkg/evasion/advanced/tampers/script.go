// Package tampers — Tengo-based tamper plugin loader.
// Allows users to write custom tamper scripts in .tengo files.
// Scripts run in a sandboxed VM with only safe stdlib modules.
package tampers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/d5/tengo/v2"
	"github.com/d5/tengo/v2/stdlib"
)

// ScriptTamper wraps a Tengo script as a Tamper interface implementation.
type ScriptTamper struct {
	BaseTamper
	scriptBytes []byte
	compiled    *tengo.Compiled // pre-compiled script for Clone()-based execution
}

// safeModules are the only Tengo stdlib modules available to scripts.
// No file I/O, no network, no OS access, no insecure randomness.
var safeModules = stdlib.GetModuleMap("text", "fmt", "math", "times")

// LoadScriptTamper compiles a .tengo file and extracts metadata.
// The script must define: name (string), description (string), transform (function).
// Optional: category (string), priority (int), tags (array of strings).
func LoadScriptTamper(path string) (*ScriptTamper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tamper script %s: %w", path, err)
	}

	script := tengo.NewScript(data)
	script.SetImports(safeModules)
	script.SetMaxAllocs(10_000_000)

	compiled, err := script.Run()
	if err != nil {
		return nil, fmt.Errorf("compile tamper script %s: %w", path, err)
	}

	nameVar := compiled.Get("name")
	if nameVar.IsUndefined() {
		return nil, fmt.Errorf("tamper script %s: missing 'name' variable", path)
	}
	descVar := compiled.Get("description")
	if descVar.IsUndefined() {
		return nil, fmt.Errorf("tamper script %s: missing 'description' variable", path)
	}
	transformVar := compiled.Get("transform")
	if transformVar.IsUndefined() {
		return nil, fmt.Errorf("tamper script %s: missing 'transform' function", path)
	}

	catStr := "custom"
	if cat := compiled.Get("category"); !cat.IsUndefined() {
		catStr = cat.String()
	}

	priority := PriorityNormal
	if pri := compiled.Get("priority"); !pri.IsUndefined() {
		priority = Priority(pri.Int())
	}

	var tags []string
	if tagsVar := compiled.Get("tags"); !tagsVar.IsUndefined() {
		// Tengo arrays are []interface{} internally
		if obj := tagsVar.Value(); obj != nil {
			if arr, ok := obj.([]interface{}); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						tags = append(tags, s)
					}
				}
			}
		}
	}

	st := &ScriptTamper{
		BaseTamper: NewBaseTamper(
			nameVar.String(),
			descVar.String(),
			Category(catStr),
			priority,
			tags...,
		),
		scriptBytes: data,
	}

	// Pre-compile the transform wrapper so Transform() only needs Clone()
	if err := st.precompile(); err != nil {
		return nil, err
	}

	return st, nil
}

// precompile creates the wrapper script and compiles it once.
// Uses Compile() (not Run()) so the transform function isn't invoked at load time.
// The compiled result is cloned per-Transform call, avoiding recompilation.
func (s *ScriptTamper) precompile() error {
	wrapper := fmt.Sprintf(`%s
__result__ := transform(__input__)
`, string(s.scriptBytes))

	script := tengo.NewScript([]byte(wrapper))
	script.SetImports(safeModules)
	script.SetMaxAllocs(10_000_000)
	_ = script.Add("__input__", "")

	compiled, err := script.Compile()
	if err != nil {
		return fmt.Errorf("precompile tamper %s: %w", s.Name(), err)
	}
	s.compiled = compiled
	return nil
}

// Transform applies the script's transform function to the payload.
// Uses Clone() on the pre-compiled script for thread-safe, zero-recompilation execution.
func (s *ScriptTamper) Transform(payload string) (result string) {
	result = payload // default on panic or error

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tamper] panic in script %s: %v", s.Name(), r)
			result = payload
		}
	}()

	c := s.compiled.Clone()
	if err := c.Set("__input__", payload); err != nil {
		return payload
	}
	if err := c.Run(); err != nil {
		return payload
	}

	scriptResult := c.Get("__result__")
	if scriptResult.IsUndefined() {
		return payload
	}
	return scriptResult.String()
}

// TransformRequest returns nil — script tampers only modify payloads, not requests.
func (s *ScriptTamper) TransformRequest(_ *http.Request) *http.Request { return nil }

// LoadScriptDir loads all .tengo files from a directory.
// Files that fail to load are returned as errors but don't prevent loading others.
func LoadScriptDir(dir string) ([]*ScriptTamper, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{fmt.Errorf("read plugin dir %s: %w", dir, err)}
	}

	var tampers []*ScriptTamper
	var errs []error

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tengo") {
			continue
		}
		st, err := LoadScriptTamper(filepath.Join(dir, entry.Name()))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		tampers = append(tampers, st)
	}
	return tampers, errs
}
