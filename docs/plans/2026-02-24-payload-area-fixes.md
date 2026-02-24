# Payload Area Bug Fixes Implementation Plan

> **For Copilot:** Follow this plan task-by-task using TDD discipline. Load `.github/skills/autonomous-completion/SKILL.md` first.

**Goal:** Fix 5 confirmed bugs in the payload subsystem — vendor filter mismatch, slice aliasing, case mutator corruption, missing locks, and silent payload skip.

**Architecture:** Three files to edit (`database.go`, `loader.go`, `mutators.go`), all in `pkg/payloads/` and `pkg/payloadgen/`. Each fix is independent and can be verified in isolation. Order: F3 (smallest, isolated) → F4 (locks, enables safe F2) → F2 (slice copies) → F1 (vendor filter) → F6 (logging).

**Tech Stack:** Go 1.24+, `sync.RWMutex`, `strings`, `log`, `unicode`

---

## Progress Tracker

| # | Status | File | Fix | Description |
|---|--------|------|-----|-------------|
| 1 | ⬜ | `pkg/payloadgen/mutators.go:37` | F3 | Guard XOR with ASCII letter check |
| 2 | ⬜ | `pkg/payloads/database.go:133` | F4 | Add RLock to `Categories()` |
| 3 | ⬜ | `pkg/payloads/database.go:141` | F4 | Add RLock to `Vendors()` |
| 4 | ⬜ | `pkg/payloads/database.go:150` | F4 | Add RLock to `Tags()` |
| 5 | ⬜ | `pkg/payloads/database.go:159` | F4 | Add RLock to `Search()` |
| 6 | ⬜ | `pkg/payloads/database.go:170` | F4 | Add RLock to `Filter()` |
| 7 | ⬜ | `pkg/payloads/database.go:97` | F2 | `All()` return copy |
| 8 | ⬜ | `pkg/payloads/database.go:108` | F2 | `ByCategory()` return copy |
| 9 | ⬜ | `pkg/payloads/database.go:114` | F2 | `ByVendor()` return copy |
| 10 | ⬜ | `pkg/payloads/database.go:120` | F2 | `ByTag()` return copy |
| 11 | ⬜ | `pkg/payloads/database.go:126` | F2 | `BySeverity()` return copy |
| 12 | ⬜ | `pkg/payloads/database.go:~267` | F1 | Vendor filter check `p.Vendor` field |
| 13 | ⬜ | `pkg/payloads/loader.go:203-206` | F6 | Log skipped payloads + add `"log"` import |
| 14 | ⬜ | `pkg/payloadgen/mutators_test.go` | T1 | Test: CaseMutator non-letter preservation |
| 15 | ⬜ | `pkg/payloads/database_test.go` | T2 | Test: `All()` returns independent copy |
| 16 | ⬜ | `pkg/payloads/database_test.go` | T3 | Test: `ByCategory()` returns independent copy |
| 17 | ⬜ | `pkg/payloads/database_test.go` | T4 | Test: vendor filter matches `p.Vendor` field |
| 18 | ⬜ | `pkg/payloads/database_test.go` | T5 | Test: concurrent read/write safety |
| 19 | ⬜ | — | V1 | `go test -v -race ./pkg/payloads/... ./pkg/payloadgen/...` |
| 20 | ⬜ | — | V2 | `go build ./...` |
| 21 | ⬜ | — | V3 | `golangci-lint run` |
| 22 | ⬜ | — | V4 | `git commit` (no push) |

---

## Prerequisite: Baseline

Before any edits, capture the baseline:

```bash
go test -v -race ./pkg/payloads/... ./pkg/payloadgen/...
```

All existing tests must pass. If any fail, fix them first.

---

## Task 1: Fix F3 — CaseMutator XOR corrupts non-letters

**File:** `pkg/payloadgen/mutators.go:37`

**Problem:** `ch ^ 0x20` toggles bit 5, which only works for ASCII letters (`A-Z`, `a-z`). Applied to digits, symbols, or Unicode characters it produces garbage (e.g., `'1' ^ 0x20` = `'\x11'`).

**Step 1: Write the failing test**

Create `pkg/payloadgen/mutators_test.go` (or add to existing):

```go
func TestCaseMutator_NonLetterPreservation(t *testing.T) {
    m := &CaseMutator{MaxVariants: 50}

    // Payload with digits, symbols, and Unicode — none should be corrupted
    payload := "SELECT 1+1 FROM tbl WHERE id=42 — «test»"

    for _, variant := range m.Mutate(payload) {
        for i, ch := range variant {
            orig := []rune(payload)[i]
            if !isASCIILetter(orig) && ch != orig {
                t.Errorf("non-letter rune at position %d changed: %q → %q", i, string(orig), string(ch))
            }
        }
    }
}

func isASCIILetter(r rune) bool {
    return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}
```

**Step 2: Run the test — expect FAIL**

```bash
go test -v -race ./pkg/payloadgen/... -run TestCaseMutator_NonLetterPreservation
```

**Step 3: Fix the code**

In `pkg/payloadgen/mutators.go`, line 37, change:

```go
// BEFORE (line 37-38):
if rand.Intn(2) == 0 {
    b.WriteRune(ch ^ 0x20) // toggle ASCII case
```

To:

```go
// AFTER:
if rand.Intn(2) == 0 && ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
    b.WriteRune(ch ^ 0x20) // toggle ASCII case
```

**Step 4: Run test — expect PASS**

```bash
go test -v -race ./pkg/payloadgen/... -run TestCaseMutator_NonLetterPreservation
```

**Step 5: Commit**

```bash
git add pkg/payloadgen/mutators.go pkg/payloadgen/mutators_test.go
git commit -m "fix(payloads): guard CaseMutator XOR against non-letter runes"
```

---

## Task 2: Fix F4 — Missing RLock on read-only methods

**File:** `pkg/payloads/database.go` — lines 133, 141, 150, 159, 170

**Problem:** `Categories()`, `Vendors()`, `Tags()`, `Search()`, and `Filter()` iterate internal maps/slices without holding `db.mu.RLock()`. Concurrent `Add()` calls cause data races.

**Step 1: Write the failing test**

Add to `pkg/payloads/database_test.go`:

```go
func TestDatabase_ConcurrentAccess(t *testing.T) {
    db := NewDatabase()

    // Pre-populate
    for i := 0; i < 100; i++ {
        db.Add(Payload{
            Payload:      fmt.Sprintf("test-%d", i),
            Category:     "sqli",
            Vendor:       "cloudflare",
            Tags:         []string{"evasion"},
            SeverityHint: "high",
        })
    }

    var wg sync.WaitGroup
    // Writer goroutine
    wg.Add(1)
    go func() {
        defer wg.Done()
        for i := 0; i < 100; i++ {
            db.Add(Payload{
                Payload:  fmt.Sprintf("concurrent-%d", i),
                Category: "xss",
                Vendor:   "akamai",
            })
        }
    }()

    // Reader goroutines — exercise all read methods
    for _, fn := range []func(){
        func() { db.Categories() },
        func() { db.Vendors() },
        func() { db.Tags() },
        func() { db.Search("test") },
        func() { db.Filter(WithCategories("sqli")) },
        func() { db.All() },
        func() { db.ByCategory("sqli") },
        func() { db.ByVendor("cloudflare") },
    } {
        fn := fn
        wg.Add(1)
        go func() {
            defer wg.Done()
            for i := 0; i < 100; i++ {
                fn()
            }
        }()
    }

    wg.Wait()
}
```

**Step 2: Run with `-race` — expect FAIL (data race detected)**

```bash
go test -v -race ./pkg/payloads/... -run TestDatabase_ConcurrentAccess
```

**Step 3: Add RLock to all 5 methods**

`Categories()` (line 133):
```go
func (db *Database) Categories() []string {
    db.mu.RLock()
    defer db.mu.RUnlock()
    cats := make([]string, 0, len(db.byCategory))
    // ... rest unchanged
```

`Vendors()` (line 141):
```go
func (db *Database) Vendors() []string {
    db.mu.RLock()
    defer db.mu.RUnlock()
    vendors := make([]string, 0, len(db.byVendor))
    // ... rest unchanged
```

`Tags()` (line 150):
```go
func (db *Database) Tags() []string {
    db.mu.RLock()
    defer db.mu.RUnlock()
    tags := make([]string, 0, len(db.byTag))
    // ... rest unchanged
```

`Search()` (line 159):
```go
func (db *Database) Search(query string) []Payload {
    db.mu.RLock()
    defer db.mu.RUnlock()
    query = strings.ToLower(query)
    // ... rest unchanged
```

`Filter()` (line 170):
```go
func (db *Database) Filter(opts ...FilterOption) []Payload {
    db.mu.RLock()
    defer db.mu.RUnlock()
    filter := &PayloadFilter{}
    // ... rest unchanged
```

**Step 4: Run test — expect PASS (no race)**

```bash
go test -v -race ./pkg/payloads/... -run TestDatabase_ConcurrentAccess
```

**Step 5: Commit**

```bash
git add pkg/payloads/database.go pkg/payloads/database_test.go
git commit -m "fix(payloads): add missing RLock to Categories/Vendors/Tags/Search/Filter"
```

---

## Task 3: Fix F2 — Slice aliasing exposes internal state

**File:** `pkg/payloads/database.go` — lines 97, 108, 114, 120, 126

**Problem:** `All()`, `ByCategory()`, `ByVendor()`, `ByTag()`, `BySeverity()` return direct references to internal slices. Callers can mutate the database's state by appending or modifying returned slices.

**Step 1: Write the failing test**

```go
func TestDatabase_AllReturnsCopy(t *testing.T) {
    db := NewDatabase()
    db.Add(Payload{Payload: "test-1", Category: "sqli"})
    db.Add(Payload{Payload: "test-2", Category: "sqli"})

    all := db.All()
    originalLen := len(all)

    // Mutate the returned slice
    all[0].Payload = "MUTATED"

    // Original must be unchanged
    fresh := db.All()
    if fresh[0].Payload == "MUTATED" {
        t.Error("All() returned internal slice — caller mutation leaked into database")
    }
    if len(fresh) != originalLen {
        t.Errorf("database length changed: got %d, want %d", len(fresh), originalLen)
    }
}

func TestDatabase_ByCategoryReturnsCopy(t *testing.T) {
    db := NewDatabase()
    db.Add(Payload{Payload: "test-1", Category: "sqli"})

    result := db.ByCategory("sqli")
    result[0].Payload = "MUTATED"

    fresh := db.ByCategory("sqli")
    if fresh[0].Payload == "MUTATED" {
        t.Error("ByCategory() returned internal slice — caller mutation leaked into database")
    }
}
```

**Step 2: Run the test — expect FAIL**

```bash
go test -v -race ./pkg/payloads/... -run "TestDatabase_AllReturnsCopy|TestDatabase_ByCategoryReturnsCopy"
```

**Step 3: Return copies in all 5 methods**

Helper (add near top of file):

```go
// copyPayloads returns an independent copy of the slice.
func copyPayloads(src []Payload) []Payload {
    if src == nil {
        return nil
    }
    dst := make([]Payload, len(src))
    copy(dst, src)
    return dst
}
```

Then update each method:

`All()`:
```go
func (db *Database) All() []Payload {
    db.mu.RLock()
    defer db.mu.RUnlock()
    return copyPayloads(db.payloads)
}
```

`ByCategory()`:
```go
func (db *Database) ByCategory(category string) []Payload {
    db.mu.RLock()
    defer db.mu.RUnlock()
    return copyPayloads(db.byCategory[strings.ToLower(category)])
}
```

`ByVendor()`:
```go
func (db *Database) ByVendor(vendor string) []Payload {
    db.mu.RLock()
    defer db.mu.RUnlock()
    return copyPayloads(db.byVendor[strings.ToLower(vendor)])
}
```

`ByTag()`:
```go
func (db *Database) ByTag(tag string) []Payload {
    db.mu.RLock()
    defer db.mu.RUnlock()
    return copyPayloads(db.byTag[strings.ToLower(tag)])
}
```

`BySeverity()`:
```go
func (db *Database) BySeverity(severity string) []Payload {
    db.mu.RLock()
    defer db.mu.RUnlock()
    return copyPayloads(db.bySeverity[strings.ToLower(severity)])
}
```

**Step 4: Run tests — expect PASS**

```bash
go test -v -race ./pkg/payloads/... -run "TestDatabase_AllReturnsCopy|TestDatabase_ByCategoryReturnsCopy"
```

**Step 5: Commit**

```bash
git add pkg/payloads/database.go pkg/payloads/database_test.go
git commit -m "fix(payloads): return defensive copies from All/ByCategory/ByVendor/ByTag/BySeverity"
```

---

## Task 4: Fix F1 — Vendor filter only checks Notes, ignores Vendor field

**File:** `pkg/payloads/database.go:~267` (inside `matches()`)

**Problem:** The `matches()` method checks `strings.Contains(p.Notes, "vendor:"+v)` but ignores the first-class `p.Vendor` field. This is inconsistent with `addLocked()` which indexes by `p.Vendor` first. Payloads with `Vendor: "cloudflare"` but no "vendor:cloudflare" in Notes won't match the filter.

**Step 1: Write the failing test**

```go
func TestDatabase_VendorFilterMatchesVendorField(t *testing.T) {
    db := NewDatabase()
    db.Add(Payload{
        Payload:  "test-vendor-field",
        Category: "sqli",
        Vendor:   "cloudflare",
        Notes:    "some notes without vendor tag",
    })

    results := db.Filter(WithVendors("cloudflare"))
    if len(results) == 0 {
        t.Error("Filter(WithVendors) did not match payload with Vendor field set")
    }
}
```

**Step 2: Run test — expect FAIL**

```bash
go test -v -race ./pkg/payloads/... -run TestDatabase_VendorFilterMatchesVendorField
```

**Step 3: Fix the vendor match in `matches()`**

Replace the vendor check block (~line 262-270):

```go
// BEFORE:
if len(f.vendors) > 0 {
    found := false
    for _, v := range f.vendors {
        if strings.Contains(strings.ToLower(p.Notes), "vendor:"+strings.ToLower(v)) {
            found = true
            break
        }
    }
    if !found {
        return false
    }
}

// AFTER:
if len(f.vendors) > 0 {
    found := false
    for _, v := range f.vendors {
        vl := strings.ToLower(v)
        if strings.EqualFold(p.Vendor, vl) {
            found = true
            break
        }
        // Fallback: check Notes for "vendor:<name>" tags
        if strings.Contains(strings.ToLower(p.Notes), "vendor:"+vl) {
            found = true
            break
        }
    }
    if !found {
        return false
    }
}
```

**Step 4: Run test — expect PASS**

```bash
go test -v -race ./pkg/payloads/... -run TestDatabase_VendorFilterMatchesVendorField
```

**Step 5: Commit**

```bash
git add pkg/payloads/database.go pkg/payloads/database_test.go
git commit -m "fix(payloads): vendor filter now checks Vendor field before Notes fallback"
```

---

## Task 5: Fix F6 — Silent payload skip hides data problems

**File:** `pkg/payloads/loader.go:203-206`

**Problem:** Invalid payloads are skipped with only a code comment. No log output means corrupted/malformed payload files go unnoticed.

**Step 1: Add `"log"` to imports (line ~6)**

```go
import (
    "fmt"
    "io/fs"
    "log"
    "os"
    // ... rest unchanged
```

**Step 2: Replace silent skip with log warning**

```go
// BEFORE (lines 203-206):
if err := payloads[i].Validate(); err != nil {
    // Skip invalid payloads silently — they fail validation
    // but shouldn't break the entire load.
    continue
}

// AFTER:
if err := payloads[i].Validate(); err != nil {
    log.Printf("payloads: skipping invalid payload in %s (index %d): %v", path, i, err)
    continue
}
```

**Step 3: Verify build**

```bash
go build ./pkg/payloads/...
```

**Step 4: Commit**

```bash
git add pkg/payloads/loader.go
git commit -m "fix(payloads): log warning when skipping invalid payloads during load"
```

---

## Task 6: Final verification

**Step 1: Run all tests with race detector**

```bash
go test -v -race ./pkg/payloads/... ./pkg/payloadgen/...
```

**Step 2: Full build**

```bash
go build ./...
```

**Step 3: Lint**

```bash
golangci-lint run
```

**Step 4: Review diff**

```bash
git diff --stat HEAD~5
```

Verify only these files changed:
- `pkg/payloadgen/mutators.go`
- `pkg/payloadgen/mutators_test.go`
- `pkg/payloads/database.go`
- `pkg/payloads/database_test.go`
- `pkg/payloads/loader.go`

**Step 5: Squash into single commit (if preferred)**

```bash
git rebase -i HEAD~5
# Squash all into: fix(payloads): fix vendor filter, slice aliasing, missing locks, case mutator, silent skip
```

Do NOT push.

---

## Bug Reference

| ID | Severity | Summary | Root Cause |
|----|----------|---------|------------|
| F1 | High | Vendor filter ignores `p.Vendor` field | `matches()` only checks `p.Notes` for "vendor:" prefix |
| F2 | High | Slice aliasing leaks internal state | `All()`/`ByX()` return direct slice references |
| F3 | Medium | CaseMutator corrupts non-letters | `ch ^ 0x20` applied to all runes, not just ASCII letters |
| F4 | High | Data races on concurrent access | `Categories()`/`Vendors()`/`Tags()`/`Search()`/`Filter()` missing `RLock()` |
| F6 | Low | Silent payload skip hides problems | `continue` with only a code comment, no log output |

---

## Not-a-Bug (Investigated and Cleared)

| ID | Area | Finding |
|----|------|---------|
| F8 | `types.go:Normalize()` | `Normalize()` already defaults empty `Method` to `"GET"` at line 168. Not a bug. |
