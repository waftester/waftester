package jwt

import (
	"encoding/json"
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
