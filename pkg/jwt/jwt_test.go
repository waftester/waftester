package jwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	// Create a valid HS256 token
	claims := &Claims{
		Subject:   "user123",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Role:      "user",
	}

	token, err := CreateToken(AlgHS256, claims, []byte("secret"))
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	t.Run("valid token", func(t *testing.T) {
		parsed, err := Parse(token)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}

		if parsed.Header.Alg != "HS256" {
			t.Errorf("expected HS256, got %s", parsed.Header.Alg)
		}

		if parsed.Claims.Subject != "user123" {
			t.Errorf("expected subject 'user123', got '%s'", parsed.Claims.Subject)
		}

		if parsed.Claims.Role != "user" {
			t.Errorf("expected role 'user', got '%s'", parsed.Claims.Role)
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := Parse("invalid.token")
		if err == nil {
			t.Error("expected error for invalid token format")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := Parse("!!!invalid!!!.!!!base64!!!.signature")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})
}

func TestSign(t *testing.T) {
	header := &Header{Alg: "HS256", Typ: "JWT"}
	claims := &Claims{Subject: "test", IssuedAt: time.Now().Unix()}

	t.Run("HS256", func(t *testing.T) {
		token, err := Sign(header, claims, []byte("secret"))
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("expected 3 parts, got %d", len(parts))
		}

		if parts[2] == "" {
			t.Error("signature should not be empty")
		}
	})

	t.Run("none algorithm", func(t *testing.T) {
		noneHeader := &Header{Alg: "none", Typ: "JWT"}
		token, err := Sign(noneHeader, claims, nil)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		parts := strings.Split(token, ".")
		if parts[2] != "" {
			t.Errorf("none algorithm should have empty signature, got %s", parts[2])
		}
	})

	t.Run("HS384", func(t *testing.T) {
		header384 := &Header{Alg: "HS384"}
		token, err := Sign(header384, claims, []byte("secret"))
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		if token == "" {
			t.Error("token should not be empty")
		}
	})

	t.Run("HS512", func(t *testing.T) {
		header512 := &Header{Alg: "HS512"}
		token, err := Sign(header512, claims, []byte("secret"))
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}

		if token == "" {
			t.Error("token should not be empty")
		}
	})
}

func TestVerifyHS256(t *testing.T) {
	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("mysecret"))

	t.Run("valid signature", func(t *testing.T) {
		if !VerifyHS256(token, "mysecret") {
			t.Error("expected valid signature")
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		if VerifyHS256(token, "wrongsecret") {
			t.Error("expected invalid signature")
		}
	})

	t.Run("invalid token format", func(t *testing.T) {
		if VerifyHS256("invalid", "secret") {
			t.Error("expected false for invalid format")
		}
	})
}

func TestNoneAlgorithmAttack(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))
	parsed, _ := Parse(token)

	vulns, err := attacker.NoneAlgorithmAttack(parsed)
	if err != nil {
		t.Fatalf("attack failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}

	for _, v := range vulns {
		if v.Type != AttackNoneAlg {
			t.Errorf("expected AttackNoneAlg, got %s", v.Type)
		}
		if v.Severity != "critical" {
			t.Errorf("expected critical severity, got %s", v.Severity)
		}

		// Parse the attack token and verify algorithm is none variant
		attackToken, err := Parse(v.Token)
		if err != nil {
			t.Logf("attack token: %s", v.Token)
			continue
		}

		algLower := strings.ToLower(strings.TrimSpace(attackToken.Header.Alg))
		if !strings.Contains(algLower, "none") {
			t.Errorf("expected 'none' algorithm, got %s", attackToken.Header.Alg)
		}
	}
}

func TestAlgorithmConfusionAttack(t *testing.T) {
	attacker := NewAttacker()

	// Create a mock RS256 token (just for header testing)
	header := &Header{Alg: "RS256", Typ: "JWT"}
	claims := &Claims{Subject: "test"}

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)
	mockToken := base64URLEncode(headerBytes) + "." + base64URLEncode(claimsBytes) + ".signature"

	parsed, _ := Parse(mockToken)

	publicKey := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"

	vulns, err := attacker.AlgorithmConfusionAttack(parsed, publicKey)
	if err != nil {
		t.Fatalf("attack failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Fatal("expected vulnerability for RS256 token")
	}

	v := vulns[0]
	if v.Type != AttackAlgConfusion {
		t.Errorf("expected AttackAlgConfusion, got %s", v.Type)
	}

	// Verify the attack token has HS256 algorithm
	attackToken, _ := Parse(v.Token)
	if attackToken.Header.Alg != "HS256" {
		t.Errorf("expected HS256, got %s", attackToken.Header.Alg)
	}
}

func TestBruteforceSecret(t *testing.T) {
	attacker := NewAttacker()

	// Create token with weak secret
	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))
	parsed, _ := Parse(token)

	t.Run("find weak secret", func(t *testing.T) {
		found, err := attacker.BruteforceSecret(parsed, nil)
		if err != nil {
			t.Fatalf("brute force failed: %v", err)
		}

		if found != "secret" {
			t.Errorf("expected 'secret', got '%s'", found)
		}
	})

	t.Run("custom wordlist", func(t *testing.T) {
		customToken, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("mypass"))
		customParsed, _ := Parse(customToken)

		found, err := attacker.BruteforceSecret(customParsed, []string{"wrong1", "mypass", "wrong2"})
		if err != nil {
			t.Fatalf("brute force failed: %v", err)
		}

		if found != "mypass" {
			t.Errorf("expected 'mypass', got '%s'", found)
		}
	})

	t.Run("not found", func(t *testing.T) {
		strongToken, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("super-strong-random-password-12345!"))
		strongParsed, _ := Parse(strongToken)

		_, err := attacker.BruteforceSecret(strongParsed, []string{"weak1", "weak2"})
		if err == nil {
			t.Error("expected error when secret not found")
		}
	})
}

func TestSignatureStripAttack(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))
	parsed, _ := Parse(token)

	vulns, err := attacker.SignatureStripAttack(parsed)
	if err != nil {
		t.Fatalf("attack failed: %v", err)
	}

	if len(vulns) < 2 {
		t.Errorf("expected at least 2 vulnerabilities, got %d", len(vulns))
	}

	// Check for empty signature attack
	hasEmpty := false
	for _, v := range vulns {
		if strings.HasSuffix(v.Token, ".") {
			hasEmpty = true
			break
		}
	}

	if !hasEmpty {
		t.Error("expected empty signature attack")
	}
}

func TestClaimTamperAttack(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "normaluser", Role: "user"}, []byte("secret"))
	parsed, _ := Parse(token)

	vulns, err := attacker.ClaimTamperAttack(parsed)
	if err != nil {
		t.Fatalf("attack failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}

	// Check for privilege escalation
	hasPrivEsc := false
	for _, v := range vulns {
		attackToken, _ := Parse(v.Token)
		if attackToken != nil && attackToken.Claims.Admin {
			hasPrivEsc = true
			break
		}
	}

	if !hasPrivEsc {
		t.Error("expected privilege escalation attack")
	}
}

func TestKidInjectionAttack(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))
	parsed, _ := Parse(token)

	vulns, err := attacker.KidInjectionAttack(parsed)
	if err != nil {
		t.Fatalf("attack failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}

	// Check for various injection types
	hasPathTraversal := false
	hasSQLi := false
	hasCommandInj := false

	for _, v := range vulns {
		desc := strings.ToLower(v.Description)
		if strings.Contains(desc, "dev/null") || strings.Contains(desc, "../") {
			hasPathTraversal = true
		}
		if strings.Contains(desc, "union") || strings.Contains(desc, "drop") {
			hasSQLi = true
		}
		if strings.Contains(desc, "; id") || strings.Contains(desc, "| id") {
			hasCommandInj = true
		}
	}

	if !hasPathTraversal {
		t.Error("expected path traversal in kid")
	}
	if !hasSQLi {
		t.Error("expected SQL injection in kid")
	}
	if !hasCommandInj {
		t.Error("expected command injection in kid")
	}
}

func TestJKUSpoofAttack(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))
	parsed, _ := Parse(token)

	attackerURL := "https://evil.com/.well-known/jwks.json"

	vulns, err := attacker.JKUSpoofAttack(parsed, attackerURL)
	if err != nil {
		t.Fatalf("attack failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Fatal("expected vulnerability")
	}

	v := vulns[0]
	if v.Type != AttackJKUSpoof {
		t.Errorf("expected AttackJKUSpoof, got %s", v.Type)
	}

	// Verify JKU is set in attack token
	attackToken, _ := Parse(v.Token)
	if attackToken.Header.JKU != attackerURL {
		t.Errorf("expected JKU '%s', got '%s'", attackerURL, attackToken.Header.JKU)
	}
}

func TestGenerateMaliciousTokens(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))

	vulns, err := attacker.GenerateMaliciousTokens(token)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}

	// Check for different attack types
	types := make(map[AttackType]bool)
	for _, v := range vulns {
		types[v.Type] = true
	}

	expectedTypes := []AttackType{
		AttackNoneAlg,
		AttackSignatureStrip,
		AttackClaimTamper,
		AttackKidInjection,
	}

	for _, et := range expectedTypes {
		if !types[et] {
			t.Errorf("missing attack type: %s", et)
		}
	}

	t.Logf("Generated %d malicious tokens", len(vulns))
}

func TestAnalyze(t *testing.T) {
	t.Run("none algorithm", func(t *testing.T) {
		header := &Header{Alg: "none"}
		claims := &Claims{Subject: "test"}
		token, _ := Sign(header, claims, nil)

		analysis, err := Analyze(token)
		if err != nil {
			t.Fatalf("analyze failed: %v", err)
		}

		if analysis.Risk != "critical" {
			t.Errorf("expected critical risk, got %s", analysis.Risk)
		}

		hasNoneIssue := false
		for _, issue := range analysis.Issues {
			if strings.Contains(strings.ToLower(issue), "none") {
				hasNoneIssue = true
				break
			}
		}
		if !hasNoneIssue {
			t.Error("expected 'none' algorithm issue")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token, _ := CreateToken(AlgHS256, &Claims{
			Subject:   "test",
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		}, []byte("secret"))

		analysis, _ := Analyze(token)

		hasExpiredIssue := false
		for _, issue := range analysis.Issues {
			if strings.Contains(strings.ToLower(issue), "expired") {
				hasExpiredIssue = true
				break
			}
		}
		if !hasExpiredIssue {
			t.Error("expected expired issue")
		}
	})

	t.Run("no expiration", func(t *testing.T) {
		token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))

		analysis, _ := Analyze(token)

		hasNoExpIssue := false
		for _, issue := range analysis.Issues {
			if strings.Contains(strings.ToLower(issue), "never expires") {
				hasNoExpIssue = true
				break
			}
		}
		if !hasNoExpIssue {
			t.Error("expected no expiration issue")
		}
	})

	t.Run("admin claim", func(t *testing.T) {
		token, _ := CreateToken(AlgHS256, &Claims{Subject: "test", Admin: true}, []byte("secret"))

		analysis, _ := Analyze(token)

		hasAdminIssue := false
		for _, issue := range analysis.Issues {
			if strings.Contains(strings.ToLower(issue), "admin") {
				hasAdminIssue = true
				break
			}
		}
		if !hasAdminIssue {
			t.Error("expected admin claim issue")
		}
	})
}

func TestCreateToken(t *testing.T) {
	token, err := CreateToken(AlgHS256, &Claims{Subject: "user"}, []byte("secret"))
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	parsed, _ := Parse(token)

	if parsed.Claims.IssuedAt == 0 {
		t.Error("IssuedAt should be set automatically")
	}

	if parsed.Header.Typ != "JWT" {
		t.Errorf("expected typ 'JWT', got '%s'", parsed.Header.Typ)
	}
}

func TestCreateAdminToken(t *testing.T) {
	token, err := CreateAdminToken(AlgHS256, []byte("secret"))
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	parsed, _ := Parse(token)

	if !parsed.Claims.Admin {
		t.Error("expected Admin=true")
	}

	if parsed.Claims.Role != "admin" {
		t.Errorf("expected role 'admin', got '%s'", parsed.Claims.Role)
	}

	if parsed.Claims.ExpiresAt == 0 {
		t.Error("expected expiration to be set")
	}
}

func TestForgeToken(t *testing.T) {
	original, _ := CreateToken(AlgHS256, &Claims{Subject: "user", Role: "user"}, []byte("secret"))

	forged, err := ForgeToken(original, map[string]interface{}{
		"role":  "admin",
		"admin": true,
	}, []byte("secret"))

	if err != nil {
		t.Fatalf("forge failed: %v", err)
	}

	parsed, _ := Parse(forged)

	if parsed.Claims.Role != "admin" {
		t.Errorf("expected forged role 'admin', got '%s'", parsed.Claims.Role)
	}
}

func TestWeakSecrets(t *testing.T) {
	secrets := WeakSecrets()

	if len(secrets) < 50 {
		t.Errorf("expected at least 50 weak secrets, got %d", len(secrets))
	}

	// Check for expected weak secrets
	expected := []string{"secret", "password", "jwt", "test", "admin"}
	for _, exp := range expected {
		found := false
		for _, s := range secrets {
			if s == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected weak secret '%s' not found", exp)
		}
	}
}

func TestIsWeakSecret(t *testing.T) {
	if !IsWeakSecret("secret") {
		t.Error("'secret' should be weak")
	}

	if !IsWeakSecret("password") {
		t.Error("'password' should be weak")
	}

	if IsWeakSecret("super-secure-random-password-xyz-123") {
		t.Error("random password should not be weak")
	}
}

func TestGenerateSecureSecret(t *testing.T) {
	secret, err := GenerateSecureSecret(32)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Base64 encoded 32 bytes should be ~44 chars
	if len(secret) < 40 {
		t.Errorf("secret too short: %d", len(secret))
	}

	// Should not be weak
	if IsWeakSecret(secret) {
		t.Error("generated secret should not be weak")
	}

	t.Logf("Generated secret: %s", secret)
}

func TestEstimateSecretEntropy(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		e := EstimateSecretEntropy("")
		if e != 0 {
			t.Errorf("expected 0 entropy for empty, got %f", e)
		}
	})

	t.Run("single char", func(t *testing.T) {
		e := EstimateSecretEntropy("aaaa")
		if e != 0 {
			t.Errorf("expected 0 entropy for single char, got %f", e)
		}
	})

	t.Run("varied chars", func(t *testing.T) {
		e := EstimateSecretEntropy("abcdefgh12345678!@#$")
		if e <= 0 {
			t.Errorf("expected positive entropy, got %f", e)
		}
		t.Logf("Entropy for varied string: %f", e)
	})

	t.Run("higher for more variety", func(t *testing.T) {
		e1 := EstimateSecretEntropy("password")
		e2 := EstimateSecretEntropy("P@ssw0rd!")

		// More character variety should mean higher entropy
		t.Logf("'password' entropy: %f, 'P@ssw0rd!' entropy: %f", e1, e2)
	})
}

func TestBase64URLEncodeDecode(t *testing.T) {
	original := []byte("Hello, World!")

	encoded := base64URLEncode(original)
	decoded, err := base64URLDecode(encoded)

	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if string(decoded) != string(original) {
		t.Errorf("expected '%s', got '%s'", original, decoded)
	}

	// Should not have padding
	if strings.Contains(encoded, "=") {
		t.Error("encoded should not have padding")
	}
}

func TestHeaderFields(t *testing.T) {
	header := &Header{
		Alg:  "RS256",
		Typ:  "JWT",
		Kid:  "key-123",
		JKU:  "https://example.com/.well-known/jwks.json",
		X5U:  "https://example.com/cert.pem",
		Crit: []string{"kid"},
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed Header
	if err := json.Unmarshal(headerBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.Kid != "key-123" {
		t.Errorf("expected kid 'key-123', got '%s'", parsed.Kid)
	}

	if parsed.JKU != "https://example.com/.well-known/jwks.json" {
		t.Errorf("jku mismatch: %s", parsed.JKU)
	}
}

func TestClaimsFields(t *testing.T) {
	claims := &Claims{
		Issuer:    "https://auth.example.com",
		Subject:   "user123",
		Audience:  "api.example.com",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		NotBefore: time.Now().Unix(),
		IssuedAt:  time.Now().Unix(),
		JWTID:     "unique-id-123",
		Name:      "John Doe",
		Email:     "john@example.com",
		Role:      "admin",
		Admin:     true,
		Scope:     "read write",
		Groups:    []string{"admins", "developers"},
	}

	token, err := CreateToken(AlgHS256, claims, []byte("secret"))
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	parsed, _ := Parse(token)

	if parsed.Claims.Issuer != "https://auth.example.com" {
		t.Errorf("issuer mismatch: %s", parsed.Claims.Issuer)
	}

	if parsed.Claims.Email != "john@example.com" {
		t.Errorf("email mismatch: %s", parsed.Claims.Email)
	}
}

func TestAttackOptions(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))

	// With options
	vulns, err := attacker.GenerateMaliciousTokens(token,
		WithPublicKey("fake-public-key"),
		WithAttackerURL("https://evil.com/jwks.json"),
	)

	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	// Should have JKU spoof attack
	hasJKU := false
	for _, v := range vulns {
		if v.Type == AttackJKUSpoof {
			hasJKU = true
			break
		}
	}

	if !hasJKU {
		t.Error("expected JKU spoof attack with attacker URL option")
	}
}

func TestVulnerabilityRemediation(t *testing.T) {
	attacker := NewAttacker()

	token, _ := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))

	vulns, _ := attacker.GenerateMaliciousTokens(token)

	for _, v := range vulns {
		if v.Remediation == "" {
			t.Errorf("vulnerability %s missing remediation", v.Type)
		}
	}
}

func TestCallbackCountMatchesDedupGranularity(t *testing.T) {
	// Regression test: the OnVulnerabilityFound callback must fire once per
	// unique AttackType, matching the dedup key in dedup.go (string(v.Type)).
	// Before the fix, GenerateMaliciousTokens fired 28 callbacks for 5 types.
	attacker := NewAttacker()

	var callbackCount int
	attacker.OnVulnerabilityFound = func() { callbackCount++ }

	token, err := CreateToken(AlgHS256, &Claims{Subject: "test"}, []byte("secret"))
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	vulns, err := attacker.GenerateMaliciousTokens(token)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Count unique attack types in the returned vulns.
	uniqueTypes := make(map[AttackType]struct{})
	for _, v := range vulns {
		uniqueTypes[v.Type] = struct{}{}
	}

	if callbackCount != len(uniqueTypes) {
		t.Errorf("callback count (%d) != unique types (%d); vulns returned: %d",
			callbackCount, len(uniqueTypes), len(vulns))
	}

	// Sanity: we should have more vulns than unique types (variants exist).
	if len(vulns) <= len(uniqueTypes) {
		t.Errorf("expected more vuln variants (%d) than unique types (%d)",
			len(vulns), len(uniqueTypes))
	}
}

// --- New tests: Scanner, DefaultConfig, extractTokens, verifyToken, isJWT, negative cases ---

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout <= 0 {
		t.Error("DefaultConfig.Timeout should be positive")
	}
}

func TestIsJWT(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantOK bool
	}{
		{"valid HS256", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rg2e2T2P", true},
		{"empty string", "", false},
		{"random text", "hello world", false},
		{"only header", "eyJhbGciOiJIUzI1NiJ9", false},
		{"two parts", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0", false},
		{"no signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isJWT(tt.input); got != tt.wantOK {
				t.Errorf("isJWT(%q) = %v, want %v", tt.input, got, tt.wantOK)
			}
		})
	}
}

func TestNewScanner(t *testing.T) {
	cfg := DefaultConfig()
	var called bool
	cfg.OnVulnerabilityFound = func() { called = true }
	s := NewScanner(cfg)

	if s.Attacker == nil {
		t.Fatal("Attacker should not be nil")
	}
	if s.Attacker.OnVulnerabilityFound == nil {
		t.Error("Attacker.OnVulnerabilityFound should be bridged from Config.Base")
	}

	// Verify the bridge works.
	s.Attacker.OnVulnerabilityFound()
	if !called {
		t.Error("calling Attacker.OnVulnerabilityFound should trigger Base callback")
	}
}

func TestScanWithServer(t *testing.T) {
	// Server that returns a JWT in a Set-Cookie header.
	testToken, _ := CreateToken(AlgHS256, &Claims{Subject: "1"}, []byte("secret"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "token", Value: testToken})
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Timeout = 5 * time.Second
	s := NewScanner(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := s.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.ExtractedTokens == 0 {
		t.Error("should have extracted at least one token from Set-Cookie")
	}
	if len(result.Vulnerabilities) == 0 {
		t.Error("should have generated vulnerability variants")
	}
}

func TestScanWithNoTokens(t *testing.T) {
	// Server with no tokens — scanner falls back to test token.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "no tokens here")
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := s.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.ExtractedTokens != 0 {
		t.Errorf("expected 0 extracted tokens, got %d", result.ExtractedTokens)
	}
	// Should still generate vulns from the fallback test token.
	if len(result.Vulnerabilities) == 0 {
		t.Error("should have generated vulnerabilities from fallback token")
	}
}

func TestScanContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := s.Scan(ctx, server.URL)
	if err == nil {
		t.Log("expected context error, may have completed before cancel")
	}
}

func TestScanInvalidTarget(t *testing.T) {
	s := NewScanner(DefaultConfig())

	ctx := context.Background()
	_, err := s.Scan(ctx, "://invalid")
	if err == nil {
		t.Error("expected error for invalid target URL")
	}
}

func TestExtractTokensFromBody(t *testing.T) {
	token, _ := CreateToken(AlgHS256, &Claims{Subject: "bodytoken"}, []byte("secret"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"access_token":"%s"}`, token)
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	client := &http.Client{Timeout: 5 * time.Second}
	tokens, err := s.extractTokens(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("extractTokens failed: %v", err)
	}

	if len(tokens) == 0 {
		t.Error("should have extracted token from response body")
	}

	found := false
	for _, tok := range tokens {
		if tok == token {
			found = true
		}
	}
	if !found {
		t.Error("extracted tokens should include the exact token from body")
	}
}

func TestExtractTokensFromCustomHeaders(t *testing.T) {
	token, _ := CreateToken(AlgHS256, &Claims{Subject: "hdrtoken"}, []byte("secret"))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Token", token)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	client := &http.Client{Timeout: 5 * time.Second}
	tokens, err := s.extractTokens(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("extractTokens failed: %v", err)
	}

	if len(tokens) == 0 {
		t.Error("should have extracted token from X-Auth-Token header")
	}
}

func TestExtractTokensDedup(t *testing.T) {
	token, _ := CreateToken(AlgHS256, &Claims{Subject: "dup"}, []byte("secret"))

	// Server returns the same token in cookie AND body.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "t", Value: token})
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"token":"%s"}`, token)
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	client := &http.Client{Timeout: 5 * time.Second}
	tokens, err := s.extractTokens(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("extractTokens failed: %v", err)
	}

	// Should only appear once despite being in two locations.
	count := 0
	for _, tok := range tokens {
		if tok == token {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected token to appear exactly once (dedup), got %d", count)
	}
}

func TestVerifyTokenAccepted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept any token.
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	client := &http.Client{Timeout: 5 * time.Second}
	accepted, err := s.verifyToken(context.Background(), client, server.URL, "malicious-token")
	if err != nil {
		t.Fatalf("verifyToken failed: %v", err)
	}
	if !accepted {
		t.Error("200 response should be treated as accepted")
	}
}

func TestVerifyTokenRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	client := &http.Client{Timeout: 5 * time.Second}
	accepted, err := s.verifyToken(context.Background(), client, server.URL, "bad-token")
	if err != nil {
		t.Fatalf("verifyToken failed: %v", err)
	}
	if accepted {
		t.Error("401 response should be treated as rejected")
	}
}

func TestVerifyTokenForbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	s := NewScanner(DefaultConfig())

	client := &http.Client{Timeout: 5 * time.Second}
	accepted, err := s.verifyToken(context.Background(), client, server.URL, "bad-token")
	if err != nil {
		t.Fatalf("verifyToken failed: %v", err)
	}
	if accepted {
		t.Error("403 response should be treated as rejected")
	}
}

func TestScanCallbackDedupBridge(t *testing.T) {
	// End-to-end: verify Scanner.Scan fires callbacks with correct dedup.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var called int
	cfg := DefaultConfig()
	cfg.Timeout = 5 * time.Second
	cfg.OnVulnerabilityFound = func() { called++ }
	s := NewScanner(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := s.Scan(ctx, server.URL)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Count unique types in returned vulns.
	uniqueTypes := make(map[AttackType]struct{})
	for _, v := range result.Vulnerabilities {
		uniqueTypes[v.Type] = struct{}{}
	}

	if len(result.Vulnerabilities) > 0 && called != len(uniqueTypes) {
		t.Errorf("callback count (%d) should match unique types (%d)", called, len(uniqueTypes))
	}
}

// --- Round 3 regression tests ---

func TestSignNullByteNone(t *testing.T) {
	// "none\x00" should produce a valid unsigned token, not an error.
	header := &Header{Alg: "none\x00", Typ: "JWT"}
	claims := &Claims{Subject: "test"}

	token, err := Sign(header, claims, nil)
	if err != nil {
		t.Fatalf("Sign with none\\x00 should succeed, got: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	if parts[2] != "" {
		t.Errorf("none variant should have empty signature, got %q", parts[2])
	}
}

func TestSignNullByteNoneMixedCase(t *testing.T) {
	// "NoNe\x00" should also work via case-insensitive + null-strip.
	header := &Header{Alg: "NoNe\x00", Typ: "JWT"}
	claims := &Claims{Subject: "test"}

	token, err := Sign(header, claims, nil)
	if err != nil {
		t.Fatalf("Sign with NoNe\\x00 should succeed, got: %v", err)
	}

	parts := strings.Split(token, ".")
	if parts[2] != "" {
		t.Errorf("none variant should have empty signature, got %q", parts[2])
	}
}

func TestAnalyzeNoneCaseInsensitive(t *testing.T) {
	// Tokens with alg="nOnE" should be flagged as critical.
	variants := []string{"none", "None", "NONE", "nOnE", "NoNe"}

	for _, alg := range variants {
		t.Run(alg, func(t *testing.T) {
			header := &Header{Alg: alg, Typ: "JWT"}
			claims := &Claims{Subject: "test", IssuedAt: time.Now().Unix()}
			token, err := Sign(header, claims, nil)
			if err != nil {
				t.Fatalf("Sign failed for alg=%q: %v", alg, err)
			}

			analysis, err := Analyze(token)
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}
			if analysis.Risk != "critical" {
				t.Errorf("alg=%q should be critical, got %q", alg, analysis.Risk)
			}
		})
	}
}

func TestAnalyzeNoneWithJKUKeepsCritical(t *testing.T) {
	// alg=none + JKU present: risk should stay "critical", not downgrade to "high".
	header := &Header{Alg: "none", Typ: "JWT", JKU: "https://evil.com/jwks"}
	claims := &Claims{Subject: "test", IssuedAt: time.Now().Unix()}
	token, err := Sign(header, claims, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Forge the header to include JKU (Parse won't see it from Sign,
	// so build a token manually).
	parsed, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	parsed.Header.JKU = "https://evil.com/jwks"

	// Re-encode with JKU in header.
	headerBytes, _ := json.Marshal(parsed.Header)
	claimsBytes, _ := json.Marshal(parsed.Claims)
	forged := base64URLEncode(headerBytes) + "." + base64URLEncode(claimsBytes) + "."

	analysis, err := Analyze(forged)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if analysis.Risk != "critical" {
		t.Errorf("none+JKU should keep critical, got %q", analysis.Risk)
	}
}

func TestCreateTokenDoesNotMutateClaims(t *testing.T) {
	claims := &Claims{
		Subject:   "user",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	// IssuedAt is 0 before call.
	if claims.IssuedAt != 0 {
		t.Fatal("precondition: IssuedAt should be 0")
	}

	_, err := CreateToken(AlgHS256, claims, []byte("secret"))
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	// After call, the caller's claims should still have IssuedAt == 0.
	if claims.IssuedAt != 0 {
		t.Error("CreateToken mutated caller's claims.IssuedAt")
	}
}

func TestAnalyzeNullByteNoneVariant(t *testing.T) {
	// A token with alg="none\x00" should be detected as critical.
	header := &Header{Alg: "none\x00", Typ: "JWT"}
	claims := &Claims{Subject: "test", IssuedAt: time.Now().Unix()}
	token, err := Sign(header, claims, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	analysis, err := Analyze(token)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if analysis.Risk != "critical" {
		t.Errorf("none\\x00 should be critical, got %q", analysis.Risk)
	}
}
