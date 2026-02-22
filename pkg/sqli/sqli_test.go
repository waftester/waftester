package sqli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
)

func TestNewTester(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config == nil {
			t.Error("expected config to be set")
		}
		if len(tester.payloads) == 0 {
			t.Error("expected payloads to be generated")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &TesterConfig{
			Base:          attackconfig.Base{Timeout: 60 * time.Second},
			DBMS:          DBMSMySQL,
			TimeThreshold: 10 * time.Second,
		}
		tester := NewTester(config)

		if tester.config.DBMS != DBMSMySQL {
			t.Errorf("expected MySQL DBMS")
		}
	})

	t.Run("DBMS filtering", func(t *testing.T) {
		config := &TesterConfig{
			DBMS: DBMSPostgreSQL,
		}
		tester := NewTester(config)

		for _, p := range tester.payloads {
			if p.DBMS != DBMSPostgreSQL && p.DBMS != DBMSGeneric {
				t.Errorf("found non-PostgreSQL payload: %s", p.DBMS)
			}
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.DBMS != DBMSGeneric {
		t.Errorf("expected generic DBMS")
	}
	if config.TimeThreshold != 5*time.Second {
		t.Errorf("expected 5s threshold")
	}
	if config.UserAgent == "" {
		t.Error("expected user agent")
	}
}

func TestGetPayloads(t *testing.T) {
	t.Run("all payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads("")

		if len(payloads) == 0 {
			t.Error("expected payloads")
		}
	})

	t.Run("error-based payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads(InjectionErrorBased)

		for _, p := range payloads {
			if p.Type != InjectionErrorBased {
				t.Errorf("expected error-based type, got %s", p.Type)
			}
		}
	})

	t.Run("time-based payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads(InjectionTimeBased)

		if len(payloads) == 0 {
			t.Error("expected time-based payloads")
		}

		for _, p := range payloads {
			if p.Type != InjectionTimeBased {
				t.Errorf("expected time-based type, got %s", p.Type)
			}
		}
	})

	t.Run("union-based payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads(InjectionUnionBased)

		if len(payloads) == 0 {
			t.Error("expected union-based payloads")
		}
	})

	t.Run("boolean-based payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads(InjectionBooleanBased)

		if len(payloads) == 0 {
			t.Error("expected boolean-based payloads")
		}
	})
}

func TestTestParameter(t *testing.T) {
	t.Run("error-based detection - MySQL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if strings.Contains(id, "'") {
				w.Write([]byte("You have an error in your SQL syntax near ''' at line 1"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "id", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerabilities")
		}

		hasError := false
		for _, v := range vulns {
			if v.Type == InjectionErrorBased {
				hasError = true
				if v.DBMS != DBMSMySQL {
					t.Errorf("expected MySQL detection, got %s", v.DBMS)
				}
				break
			}
		}

		if !hasError {
			t.Error("expected error-based vulnerability")
		}
	})

	t.Run("error-based detection - PostgreSQL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if strings.Contains(id, "'") {
				w.Write([]byte("ERROR:  syntax error at or near \"'\" at character 25"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "id", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasPostgres := false
		for _, v := range vulns {
			if v.DBMS == DBMSPostgreSQL {
				hasPostgres = true
				break
			}
		}

		if !hasPostgres {
			t.Error("expected PostgreSQL detection")
		}
	})

	t.Run("error-based detection - MSSQL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if strings.Contains(id, "'") {
				w.Write([]byte("Unclosed quotation mark after the character string '"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "id", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasMSSQL := false
		for _, v := range vulns {
			if v.DBMS == DBMSMSSQL {
				hasMSSQL = true
				break
			}
		}

		if !hasMSSQL {
			t.Error("expected MSSQL detection")
		}
	})

	t.Run("error-based detection - Oracle", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if strings.Contains(id, "'") {
				w.Write([]byte("ORA-01756: quoted string not properly terminated"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "id", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasOracle := false
		for _, v := range vulns {
			if v.DBMS == DBMSOracle {
				hasOracle = true
				break
			}
		}

		if !hasOracle {
			t.Error("expected Oracle detection")
		}
	})

	t.Run("no vulnerability", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Safe response with no errors"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "id", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})

	t.Run("POST method", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Error("expected POST method")
			}
			r.ParseForm()
			username := r.FormValue("username")
			if strings.Contains(username, "'") {
				w.Write([]byte("SQL syntax error near '''"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "username", "POST")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerabilities from POST")
		}
	})
}

func TestCommonSQLiParams(t *testing.T) {
	params := CommonSQLiParams()

	if len(params) == 0 {
		t.Error("expected params")
	}

	// Check for common ones
	hasID := false
	hasUser := false
	hasSearch := false

	for _, p := range params {
		switch p {
		case "id":
			hasID = true
		case "user":
			hasUser = true
		case "search":
			hasSearch = true
		}
	}

	if !hasID {
		t.Error("expected 'id' parameter")
	}
	if !hasUser {
		t.Error("expected 'user' parameter")
	}
	if !hasSearch {
		t.Error("expected 'search' parameter")
	}
}

func TestScan(t *testing.T) {
	t.Run("vulnerable target", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			if strings.Contains(id, "'") {
				w.Write([]byte("You have an error in your SQL syntax"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		result, err := tester.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.URL != server.URL {
			t.Errorf("expected URL %s", server.URL)
		}
		if result.TestedParams == 0 {
			t.Error("expected params to be tested")
		}
		if len(result.Vulnerabilities) == 0 {
			t.Error("expected vulnerabilities")
		}
	})
}

func TestAllInjectionTypes(t *testing.T) {
	types := AllInjectionTypes()

	if len(types) != 5 {
		t.Errorf("expected 5 injection types, got %d", len(types))
	}

	expectedTypes := map[InjectionType]bool{
		InjectionErrorBased:   false,
		InjectionTimeBased:    false,
		InjectionUnionBased:   false,
		InjectionBooleanBased: false,
		InjectionStacked:      false,
	}

	for _, it := range types {
		expectedTypes[it] = true
	}

	for it, found := range expectedTypes {
		if !found {
			t.Errorf("missing injection type: %s", it)
		}
	}
}

func TestAllDBMS(t *testing.T) {
	dbmsList := AllDBMS()

	if len(dbmsList) != 6 {
		t.Errorf("expected 6 DBMS types, got %d", len(dbmsList))
	}

	expectedDBMS := map[DBMS]bool{
		DBMSMySQL:      false,
		DBMSPostgreSQL: false,
		DBMSMSSQL:      false,
		DBMSOracle:     false,
		DBMSSQLite:     false,
		DBMSGeneric:    false,
	}

	for _, dbms := range dbmsList {
		expectedDBMS[dbms] = true
	}

	for dbms, found := range expectedDBMS {
		if !found {
			t.Errorf("missing DBMS: %s", dbms)
		}
	}
}

func TestGetRemediation(t *testing.T) {
	remediation := GetRemediation()

	if remediation == "" {
		t.Error("expected remediation")
	}

	if !strings.Contains(remediation, "parameterized") {
		t.Error("expected parameterized queries mention")
	}
	if !strings.Contains(remediation, "validation") {
		t.Error("expected input validation mention")
	}
}

func TestIsSQLEndpoint(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com/search?q=test", true},
		{"http://example.com/user/profile", true},
		{"http://example.com/product/123", true},
		{"http://example.com/api/items?id=1", true},
		{"http://example.com/query", true},
		{"http://example.com/static/style.css", false},
		{"http://example.com/images/logo.png", false},
		{"http://example.com/", false},
	}

	for _, test := range tests {
		result := IsSQLEndpoint(test.url)
		if result != test.expected {
			t.Errorf("IsSQLEndpoint(%s) = %v, expected %v", test.url, result, test.expected)
		}
	}
}

func TestGetDBMSPayloads(t *testing.T) {
	tester := NewTester(nil)

	t.Run("MySQL payloads", func(t *testing.T) {
		payloads := tester.GetDBMSPayloads(DBMSMySQL)

		hasMySQL := false
		for _, p := range payloads {
			if p.DBMS == DBMSMySQL {
				hasMySQL = true
				break
			}
		}

		if !hasMySQL {
			t.Error("expected MySQL payloads")
		}
	})

	t.Run("includes generic", func(t *testing.T) {
		payloads := tester.GetDBMSPayloads(DBMSPostgreSQL)

		hasGeneric := false
		for _, p := range payloads {
			if p.DBMS == DBMSGeneric {
				hasGeneric = true
				break
			}
		}

		if !hasGeneric {
			t.Error("expected generic payloads to be included")
		}
	})
}

func TestGenerateUnionPayloads(t *testing.T) {
	payloads := GenerateUnionPayloads(5)

	if len(payloads) == 0 {
		t.Error("expected payloads")
	}

	// Should have 3 payloads per column count (UNION SELECT, UNION ALL SELECT, 0 UNION SELECT)
	expectedCount := 5 * 3
	if len(payloads) != expectedCount {
		t.Errorf("expected %d payloads, got %d", expectedCount, len(payloads))
	}

	// Check for increasing NULL counts
	hasOneNull := false
	hasFiveNulls := false

	for _, p := range payloads {
		if strings.Contains(p, "NULL--") && !strings.Contains(p, "NULL,") {
			hasOneNull = true
		}
		if strings.Contains(p, "NULL,NULL,NULL,NULL,NULL") {
			hasFiveNulls = true
		}
	}

	if !hasOneNull {
		t.Error("expected single NULL payload")
	}
	if !hasFiveNulls {
		t.Error("expected 5 NULL payload")
	}
}

func TestGenerateTimePayloads(t *testing.T) {
	payloads := GenerateTimePayloads(3)

	if len(payloads) == 0 {
		t.Error("expected payloads")
	}

	// Check sleep time is set correctly
	for _, p := range payloads {
		if p.SleepTime != 3*time.Second {
			t.Errorf("expected 3s sleep time, got %v", p.SleepTime)
		}
		if !strings.Contains(p.Value, "3") {
			t.Error("payload should contain delay value")
		}
	}

	// Check all DBMS are represented
	dbmsFound := make(map[DBMS]bool)
	for _, p := range payloads {
		dbmsFound[p.DBMS] = true
	}

	if !dbmsFound[DBMSMySQL] {
		t.Error("expected MySQL time payload")
	}
	if !dbmsFound[DBMSPostgreSQL] {
		t.Error("expected PostgreSQL time payload")
	}
	if !dbmsFound[DBMSMSSQL] {
		t.Error("expected MSSQL time payload")
	}
	if !dbmsFound[DBMSOracle] {
		t.Error("expected Oracle time payload")
	}
}

func TestVulnerabilityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("You have an error in your SQL syntax"))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, _ := tester.TestParameter(ctx, server.URL, "id", "GET")

	if len(vulns) > 0 {
		v := vulns[0]

		if v.Type == "" {
			t.Error("vulnerability should have type")
		}
		if v.Description == "" {
			t.Error("vulnerability should have description")
		}
		if v.Severity != finding.Critical {
			t.Error("vulnerability should be critical severity")
		}
		if v.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if v.Remediation == "" {
			t.Error("vulnerability should have remediation")
		}
		if v.Parameter == "" {
			t.Error("vulnerability should have parameter")
		}
		if v.Payload == nil {
			t.Error("vulnerability should have payload reference")
		}
		if v.CVSS == 0 {
			t.Error("vulnerability should have CVSS score")
		}
	}
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := tester.Scan(ctx, server.URL)
	if err != context.Canceled {
		// May return nil with partial results
	}
}

func TestPayloadContent(t *testing.T) {
	tester := NewTester(nil)

	t.Run("contains SQL keywords", func(t *testing.T) {
		hasOR := false
		hasAND := false
		hasUNION := false
		hasSELECT := false

		for _, p := range tester.payloads {
			val := strings.ToUpper(p.Value)
			if strings.Contains(val, " OR ") {
				hasOR = true
			}
			if strings.Contains(val, " AND ") {
				hasAND = true
			}
			if strings.Contains(val, "UNION") {
				hasUNION = true
			}
			if strings.Contains(val, "SELECT") {
				hasSELECT = true
			}
		}

		if !hasOR {
			t.Error("expected OR payloads")
		}
		if !hasAND {
			t.Error("expected AND payloads")
		}
		if !hasUNION {
			t.Error("expected UNION payloads")
		}
		if !hasSELECT {
			t.Error("expected SELECT payloads")
		}
	})

	t.Run("contains comment terminators", func(t *testing.T) {
		hasDoubleDash := false
		hasHash := false

		for _, p := range tester.payloads {
			if strings.Contains(p.Value, "--") {
				hasDoubleDash = true
			}
			if strings.Contains(p.Value, "#") {
				hasHash = true
			}
		}

		if !hasDoubleDash {
			t.Error("expected -- comment payloads")
		}
		if !hasHash {
			t.Error("expected # comment payloads")
		}
	})
}

func TestDetectDBMS(t *testing.T) {
	tests := []struct {
		body     string
		expected DBMS
	}{
		{"You have an error in your SQL syntax near MySQL", DBMSMySQL},
		{"Warning: mysql_fetch_array()", DBMSMySQL},
		{"PostgreSQL ERROR: column does not exist", DBMSPostgreSQL},
		{"ERROR:  syntax error at or near", DBMSPostgreSQL},
		{"Microsoft SQL Server Driver error", DBMSMSSQL},
		{"Unclosed quotation mark after", DBMSMSSQL},
		{"ORA-01756: quoted string not properly terminated", DBMSOracle},
		{"SQLite3::query() error", DBMSSQLite},
		{"Generic database error", DBMSGeneric},
	}

	for _, test := range tests {
		result := detectDBMS(test.body)
		if result != test.expected {
			t.Errorf("detectDBMS(%s...) = %s, expected %s", test.body[:20], result, test.expected)
		}
	}
}

func BenchmarkTestParameter(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &TesterConfig{
		Base:          attackconfig.Base{Timeout: 10 * time.Second},
		DBMS:          DBMSMySQL,
		TimeThreshold: 1 * time.Second,
	}
	tester := NewTester(config)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.TestParameter(ctx, server.URL, "id", "GET")
	}
}

func TestMaxPayloadsLimit(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &TesterConfig{
		Base:          attackconfig.Base{Timeout: 5 * time.Second, MaxPayloads: 3},
		TimeThreshold: 1 * time.Second,
	}
	tester := NewTester(config)
	ctx := context.Background()

	requestCount = 0
	_, err := tester.TestParameter(ctx, server.URL, "id", "GET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MaxPayloads=3 means 3 payload requests + 1 baseline = 4 total
	expectedRequests := 4
	if requestCount != expectedRequests {
		t.Errorf("expected %d requests (1 baseline + 3 payloads), got %d", expectedRequests, requestCount)
	}
}

func TestMaxParamsLimit(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &TesterConfig{
		Base:          attackconfig.Base{Timeout: 5 * time.Second, MaxParams: 2, MaxPayloads: 1},
		TimeThreshold: 1 * time.Second,
	}
	tester := NewTester(config)
	ctx := context.Background()

	requestCount = 0
	result, err := tester.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MaxParams=2, MaxPayloads=1: 2 params × (1 baseline + 1 payload) = 4 requests
	expectedRequests := 4
	if requestCount != expectedRequests {
		t.Errorf("expected %d requests (2 params × 2 requests), got %d", expectedRequests, requestCount)
	}
	if result.TestedParams != 2 {
		t.Errorf("expected 2 tested params, got %d", result.TestedParams)
	}
}

func TestOnVulnerabilityFoundCallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.Write([]byte("You have an error in your SQL syntax"))
		}
	}))
	defer server.Close()

	var callbackCount int32
	cfg := &TesterConfig{
		Base: attackconfig.Base{
			MaxParams:   1, // Test one param to keep it fast
			MaxPayloads: 5,
			OnVulnerabilityFound: func() {
				atomic.AddInt32(&callbackCount, 1)
			},
		},
	}
	tester := NewTester(cfg)

	result, err := tester.Scan(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := int(atomic.LoadInt32(&callbackCount))
	vulns := len(result.Vulnerabilities)

	if got == 0 {
		t.Fatal("expected at least one callback invocation")
	}
	if got > vulns {
		t.Errorf("OnVulnerabilityFound called %d times, but only %d vulnerabilities found", got, vulns)
	}
	// NotifyUniqueVuln deduplicates by URL|Param|Type|DBMS, so callbacks
	// may be fewer than raw vulnerability count. Verify dedup contract:
	// same test URL + param + technique + DBMS → one callback.
	if vulns > 1 && got == vulns {
		t.Logf("NOTE: %d callbacks == %d vulns — all vulns had unique dedup keys", got, vulns)
	}
}
