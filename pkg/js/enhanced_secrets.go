// Package js provides enhanced secret patterns based on SecretFinder research
// (https://github.com/m4ll0k/SecretFinder)
package js

import (
	"regexp"

	"github.com/waftester/waftester/pkg/regexcache"
)

// EnhancedSecretPatterns returns additional secret patterns from SecretFinder
// that complement the existing patterns in analyzer.go
func EnhancedSecretPatterns() map[string]string {
	return map[string]string{
		// ═══════════════════════════════════════════════════════════════════════════
		// ADDITIONAL CLOUD PROVIDER KEYS (not in base analyzer)
		// ═══════════════════════════════════════════════════════════════════════════

		// Alibaba Cloud
		"alibaba_access_key": `LTAI[A-Za-z0-9]{12,20}`,

		// Azure
		"azure_client_id":   `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
		"azure_storage_key": `(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`,
		"azure_sas_token":   `(?i)(?:sv|sig)=[a-zA-Z0-9%]+`,
		"azure_connection":  `(?i)AccountKey=[A-Za-z0-9+/=]{88}`,

		// DigitalOcean
		"digitalocean_token": `dop_v1_[a-f0-9]{64}`,
		"digitalocean_oauth": `doo_v1_[a-f0-9]{64}`,
		"digitalocean_space": `(?i)spaces?[_-]?(?:access)?[_-]?key["'\s:=]+([A-Z0-9]{20})`,

		// Linode
		"linode_token": `[a-f0-9]{64}`,

		// Vultr
		"vultr_api_key": `[A-Z0-9]{36}`,

		// ═══════════════════════════════════════════════════════════════════════════
		// PAYMENT PROCESSORS
		// ═══════════════════════════════════════════════════════════════════════════

		// PayPal
		"paypal_client_id":     `A[a-zA-Z0-9_-]{20,80}`,
		"paypal_client_secret": `E[a-zA-Z0-9_-]{20,80}`,
		"paypal_braintree":     `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,

		// Square
		"square_access_token": `sq0atp-[0-9A-Za-z_-]{22}`,
		"square_oauth":        `sq0csp-[0-9A-Za-z_-]{43}`,

		// Plaid
		"plaid_client_id": `[a-f0-9]{24}`,
		"plaid_secret":    `[a-f0-9]{30}`,

		// ═══════════════════════════════════════════════════════════════════════════
		// COMMUNICATION SERVICES
		// ═══════════════════════════════════════════════════════════════════════════

		// Discord
		"discord_token":   `[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`,
		"discord_webhook": `https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`,
		"discord_bot":     `(?i)discord[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\||:|<=|=>|:).{0,5}['\"]([a-zA-Z0-9_-]{59,68})['\"]`,

		// Telegram
		"telegram_bot_token": `[0-9]+:AA[0-9A-Za-z_-]{33}`,

		// Teams
		"ms_teams_webhook": `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9-]+`,

		// PagerDuty
		"pagerduty_api": `[A-Za-z0-9+_-]{20}`,

		// ═══════════════════════════════════════════════════════════════════════════
		// CI/CD AND DEVOPS
		// ═══════════════════════════════════════════════════════════════════════════

		// CircleCI
		"circleci_token": `[a-f0-9]{40}`,

		// Travis CI
		"travis_token": `[A-Za-z0-9]{22}`,

		// Jenkins
		"jenkins_api_token": `(?i)jenkins[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\||:|<=|=>|:).{0,5}['\"]([a-f0-9]{32,36})['\"]`,

		// GitLab
		"gitlab_token":        `glpat-[0-9a-zA-Z\-\_]{20}`,
		"gitlab_personal":     `glpat-[0-9a-zA-Z_-]{20}`,
		"gitlab_pipeline":     `glptt-[0-9a-f]{40}`,
		"gitlab_runner":       `GR1348941[0-9a-zA-Z_-]{20}`,
		"gitlab_deploy_token": `gldt-[0-9a-zA-Z_-]{20}`,
		"gitlab_oauth":        `gloas-[0-9a-zA-Z_-]{20}`,

		// Bitbucket
		"bitbucket_token": `(?i)bitbucket[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\||:|<=|=>|:).{0,5}['\"]([a-zA-Z0-9_-]{18,24})['\"]`,

		// ═══════════════════════════════════════════════════════════════════════════
		// SECURITY AND AUTH SERVICES
		// ═══════════════════════════════════════════════════════════════════════════

		// Auth0
		"auth0_client_id":     `[a-zA-Z0-9_-]{32}`,
		"auth0_client_secret": `[a-zA-Z0-9_-]{64}`,
		"auth0_domain":        `[a-zA-Z0-9_-]+\.auth0\.com`,

		// Okta
		"okta_api_token": `00[a-zA-Z0-9_-]{40}`,
		"okta_domain":    `[a-zA-Z0-9-]+\.okta(?:preview)?\.com`,

		// OneLogin
		"onelogin_client_id": `[a-zA-Z0-9]{32}`,

		// ═══════════════════════════════════════════════════════════════════════════
		// MONITORING AND ANALYTICS
		// ═══════════════════════════════════════════════════════════════════════════

		// New Relic
		"newrelic_license":  `[A-Fa-f0-9]{40}`,
		"newrelic_api":      `NRAK-[A-Z0-9]{27}`,
		"newrelic_insights": `NRI[IQK]-[A-Za-z0-9_-]{32}`,
		"newrelic_browser":  `NRJS-[a-f0-9]{19}`,

		// Datadog
		"datadog_api": `[a-f0-9]{32}`,
		"datadog_app": `[a-f0-9]{40}`,

		// Sentry
		"sentry_dsn":   `https://[a-f0-9]+@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+`,
		"sentry_token": `[a-f0-9]{64}`,

		// Bugsnag
		"bugsnag_key": `[a-f0-9]{32}`,

		// Rollbar
		"rollbar_token": `[a-f0-9]{32}`,

		// LogRocket
		"logrocket_app_id": `[a-z0-9]{6}/[a-z0-9-]+`,

		// ═══════════════════════════════════════════════════════════════════════════
		// DATABASE AND STORAGE
		// ═══════════════════════════════════════════════════════════════════════════

		// Supabase
		"supabase_key": `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`,
		"supabase_url": `https://[a-z]+\.supabase\.co`,

		// Firebase (additional)
		"firebase_api_key":   `AIza[0-9A-Za-z_-]{35}`,
		"firebase_messaging": `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
		"firebase_db_url":    `https://[a-zA-Z0-9-]+\.firebaseio\.com`,

		// Algolia
		"algolia_api_key": `[a-f0-9]{32}`,
		"algolia_app_id":  `[A-Z0-9]{10}`,

		// Elasticsearch
		"elasticsearch_url": `(?:https?://)?[a-zA-Z0-9-]+\.(?:es\.[a-z]+-[a-z]+-\d+\.)?(?:aws\.)?elastic(?:search)?\.(?:cloud\.es\.io|com)`,

		// ═══════════════════════════════════════════════════════════════════════════
		// EMAIL SERVICES
		// ═══════════════════════════════════════════════════════════════════════════

		// Postmark
		"postmark_api_key": `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,

		// Mailjet
		"mailjet_api_key":    `[a-f0-9]{32}`,
		"mailjet_secret_key": `[a-f0-9]{32}`,

		// SparkPost
		"sparkpost_api_key": `[a-f0-9]{40}`,

		// ═══════════════════════════════════════════════════════════════════════════
		// SOCIAL PLATFORMS
		// ═══════════════════════════════════════════════════════════════════════════

		// Instagram
		"instagram_token": `[0-9]{8,10}\.[0-9A-Za-z]{10,14}\.[a-f0-9]+`,

		// LinkedIn
		"linkedin_token": `(?i)linkedin[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\||:|<=|=>|:).{0,5}['\"]([a-zA-Z0-9_-]{16,})['\"]`,

		// Pinterest
		"pinterest_token": `(?i)pinterest[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\||:|<=|=>|:).{0,5}['\"]([a-zA-Z0-9_-]{32,})['\"]`,

		// TikTok
		"tiktok_token": `(?i)tiktok[a-z0-9_ .\-,]{0,25}(?:=|>|:=|\|\||:|<=|=>|:).{0,5}['\"]([a-zA-Z0-9_-]{24,})['\"]`,

		// ═══════════════════════════════════════════════════════════════════════════
		// MAPS AND LOCATION
		// ═══════════════════════════════════════════════════════════════════════════

		// Mapbox
		"mapbox_token": `pk\.[a-zA-Z0-9]+\.[a-zA-Z0-9_-]+`,
		"mapbox_sk":    `sk\.[a-zA-Z0-9]+\.[a-zA-Z0-9_-]+`,

		// Here Maps
		"here_api_key": `[a-zA-Z0-9_-]{43}`,

		// ═══════════════════════════════════════════════════════════════════════════
		// GENERIC HIGH-ENTROPY PATTERNS
		// ═══════════════════════════════════════════════════════════════════════════

		// Generic secret patterns (SecretFinder style)
		"possible_creds":     `(?i)(?:secret|token|password|passwd|pwd|api[_-]?key|apikey|auth|credentials?|key)[_\-]?[A-Za-z0-9_\-]*\s*[:=]\s*['"]([^'"]{8,})['"]`,
		"possible_api_key":   `(?i)["']?[A-Za-z0-9_-]*(?:api|token|key|secret|auth|password|credential|pwd)[A-Za-z0-9_-]*["']?\s*[:=]\s*["']([A-Za-z0-9_/+=.-]{16,})["']`,
		"base64_credentials": `(?i)(?:password|token|key|secret|auth)[_-]?[a-z0-9]*["':\s]*[=:]["'\s]*([A-Za-z0-9+/=]{40,})`,
		"hex_secret":         `(?i)(?:key|token|secret|password|auth)[_-]?[a-z0-9]*["':\s]*[=:]["'\s]*([a-f0-9]{32,})`,

		// UUID patterns (often used as API keys)
		"uuid_key": `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,

		// High entropy strings (potential secrets)
		"high_entropy": `(?i)(?:secret|private|auth|api)[_\-]?key["':\s]*[=:][\s]*["']?([A-Za-z0-9+/=_-]{24,})["']?`,

		// ═══════════════════════════════════════════════════════════════════════════
		// CRYPTO AND BLOCKCHAIN
		// ═══════════════════════════════════════════════════════════════════════════

		// Infura
		"infura_project_id": `[a-f0-9]{32}`,

		// Alchemy
		"alchemy_api_key": `[A-Za-z0-9_-]{32}`,

		// Private keys (Ethereum style)
		"eth_private_key": `0x[a-fA-F0-9]{64}`,

		// ═══════════════════════════════════════════════════════════════════════════
		// MISCELLANEOUS SERVICES
		// ═══════════════════════════════════════════════════════════════════════════

		// Shopify
		"shopify_api_key":    `shppa_[a-fA-F0-9]{32}`,
		"shopify_api_secret": `shpss_[a-fA-F0-9]{32}`,
		"shopify_access":     `shpat_[a-fA-F0-9]{32}`,

		// Zendesk
		"zendesk_token": `[a-zA-Z0-9]{40}`,

		// Intercom
		"intercom_api_key": `[a-z0-9=_-]{60}`,

		// Asana
		"asana_access_token": `[0-9]/[0-9]+:[A-Za-z0-9+/=]+`,

		// NPM
		"npm_token": `npm_[A-Za-z0-9]{36}`,

		// Nuget
		"nuget_api_key": `oy2[a-z0-9]{43}`,

		// PyPI
		"pypi_api_token": `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}`,

		// RubyGems
		"rubygems_api_key": `rubygems_[a-f0-9]{48}`,

		// Clojars
		"clojars_token": `CLOJARS_[a-f0-9]{60}`,
	}
}

// GetAllSecretPatterns combines base patterns with enhanced patterns
func GetAllSecretPatterns() map[string]*regexp.Regexp {
	patterns := make(map[string]*regexp.Regexp)

	// Add enhanced patterns
	for name, pattern := range EnhancedSecretPatterns() {
		if compiled, err := regexcache.Get(pattern); err == nil {
			patterns[name] = compiled
		}
	}

	return patterns
}

// SecretCategory returns the category for a secret type
func SecretCategory(secretType string) string {
	categories := map[string][]string{
		"cloud": {
			"aws_", "google_", "azure_", "alibaba_", "digitalocean_",
			"linode_", "vultr_", "firebase_", "supabase_",
		},
		"payment": {
			"stripe_", "paypal_", "square_", "plaid_", "braintree",
		},
		"communication": {
			"slack_", "discord_", "telegram_", "teams_", "pagerduty_",
			"twilio_", "mailgun_", "sendgrid_", "mailchimp_", "postmark_",
			"mailjet_", "sparkpost_",
		},
		"auth": {
			"auth0_", "okta_", "onelogin_", "jwt_", "bearer_",
			"basic_auth", "oauth", "github_", "gitlab_", "bitbucket_",
		},
		"monitoring": {
			"newrelic_", "datadog_", "sentry_", "bugsnag_", "rollbar_",
			"logrocket_",
		},
		"database": {
			"mongodb_", "postgres_", "mysql_", "redis_", "algolia_",
			"elasticsearch_",
		},
		"ci_cd": {
			"circleci_", "travis_", "jenkins_", "gitlab_pipeline",
			"gitlab_runner",
		},
		"crypto": {
			"infura_", "alchemy_", "eth_private_key",
		},
		"social": {
			"facebook_", "twitter_", "instagram_", "linkedin_",
			"pinterest_", "tiktok_",
		},
		"package_registry": {
			"npm_", "nuget_", "pypi_", "rubygems_", "clojars_",
		},
	}

	for category, prefixes := range categories {
		for _, prefix := range prefixes {
			if len(secretType) >= len(prefix) && secretType[:len(prefix)] == prefix {
				return category
			}
		}
	}

	return "generic"
}

// SecretSeverity returns the severity level for a secret type
func SecretSeverity(secretType string) string {
	critical := []string{
		"aws_secret_key", "google_oauth", "private_key", "eth_private_key",
		"stripe_key", "paypal_client_secret", "firebase_key", "supabase_key",
		"azure_storage_key", "azure_connection", "mongodb_uri", "postgres_uri",
		"mysql_uri", "github_token", "gitlab_token", "npm_token",
	}

	high := []string{
		"aws_access_key", "google_api_key", "github_oauth", "slack_token",
		"discord_token", "telegram_bot_token", "jwt_token", "bearer_token",
		"api_key_generic", "authorization_header", "password_field",
		"possible_creds", "high_entropy",
	}

	for _, s := range critical {
		if secretType == s {
			return "critical"
		}
	}

	for _, s := range high {
		if secretType == s {
			return "high"
		}
	}

	return "medium"
}
