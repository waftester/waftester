// Package fp provides the benign corpus for false positive testing.
// Includes: Leipzig corpus, edge cases, form data, and API payloads.
package fp

import (
	"strings"
)

// Corpus holds all benign payload collections
type Corpus struct {
	sources map[string][]string
}

// NewCorpus creates a new corpus manager
func NewCorpus() *Corpus {
	return &Corpus{
		sources: make(map[string][]string),
	}
}

// Load loads the specified corpus sources
func (c *Corpus) Load(sources []string) error {
	for _, source := range sources {
		switch source {
		case "leipzig":
			c.sources["leipzig"] = getLeipzigCorpus()
		case "edgecases":
			c.sources["edgecases"] = getEdgeCases()
		case "forms":
			c.sources["forms"] = getFormData()
		case "api":
			c.sources["api"] = getAPIPayloads()
		case "technical":
			c.sources["technical"] = getTechnicalContent()
		case "international":
			c.sources["international"] = getInternationalNames()
		}
	}
	return nil
}

// Get returns payloads for a specific source
func (c *Corpus) Get(source string) []string {
	return c.sources[source]
}

// All returns all loaded payloads
func (c *Corpus) All() []string {
	var all []string
	for _, payloads := range c.sources {
		all = append(all, payloads...)
	}
	return all
}

// Count returns total payload count
func (c *Corpus) Count() int {
	count := 0
	for _, payloads := range c.sources {
		count += len(payloads)
	}
	return count
}

// getLeipzigCorpus returns common web sentences that should NOT trigger WAF rules
// Based on Leipzig Corpora Collection - common English sentences from web
func getLeipzigCorpus() []string {
	return []string{
		// Common sentences
		"The quick brown fox jumps over the lazy dog",
		"Hello, how can I help you today?",
		"Please enter your email address to continue",
		"Thank you for your purchase",
		"Your order has been confirmed",
		"We will process your request shortly",
		"Please check your inbox for confirmation",
		"The meeting is scheduled for next Tuesday",
		"Our team is working on this issue",
		"Please contact support if you need assistance",

		// Business content
		"Quarterly revenue increased by 15% year over year",
		"The company announced new product features",
		"Customer satisfaction scores improved significantly",
		"We are committed to delivering quality service",
		"Annual report will be published next month",
		"Strategic planning session scheduled for Monday",
		"Budget allocation for Q3 has been approved",
		"Employee training program starts next week",
		"Market analysis indicates strong growth potential",
		"Partnership agreement finalized with vendor",

		// Technical documentation (benign)
		"The function returns a boolean value",
		"Please refer to the documentation for details",
		"Configuration settings can be modified in the admin panel",
		"Database migration completed successfully",
		"API endpoint accepts JSON formatted requests",
		"Authentication token expires after 24 hours",
		"User permissions are managed through roles",
		"Cache invalidation occurs every 5 minutes",
		"Log files are rotated daily at midnight",
		"Backup process runs automatically each night",

		// E-commerce
		"Add to cart and proceed to checkout",
		"Free shipping on orders over $50",
		"Your discount code has been applied",
		"Estimated delivery: 3-5 business days",
		"Product is currently out of stock",
		"Subscribe to our newsletter for updates",
		"Returns accepted within 30 days",
		"Gift wrapping available at checkout",
		"Price match guarantee on all items",
		"Customer reviews help others decide",

		// Support content
		"How do I reset my password?",
		"Where can I track my order?",
		"What payment methods do you accept?",
		"Can I change my shipping address?",
		"How do I cancel my subscription?",
		"Is there a mobile app available?",
		"What are your business hours?",
		"Do you offer international shipping?",
		"How can I update my profile?",
		"Where can I find my invoice?",
	}
}

// getEdgeCases returns content that looks suspicious but is legitimate
// These often trigger false positives in aggressive WAF configurations
func getEdgeCases() []string {
	return []string{
		// SQL keywords in normal context
		"Please select your preferred option",
		"Select the date from the calendar",
		"Drop us a message anytime",
		"Union members receive special discounts",
		"Insert your card and enter PIN",
		"Delete old messages to free space",
		"Update your profile information",
		"Alter your notification preferences",
		"Execute your plan with confidence",
		"Grant access to team members",

		// Script/code words in normal context
		"The script was written by a famous playwright",
		"Alert me when the package arrives",
		"This event handler processes requests",
		"The onclick behavior is intuitive",
		"Document the process thoroughly",
		"Cookie preferences can be updated",
		"The window opens at 9 AM",
		"Location services improve accuracy",
		"Navigate to the settings page",
		"Frame the picture and hang it",

		// Path-like content
		"Our parent company is located in Boston",
		"The /home directory contains user files",
		"Navigate to etc folder for configs",
		"Check the Windows registry settings",
		"The admin panel is user-friendly",
		"System32 contains important files",

		// HTML/XML-like content in text
		"Use <brackets> for emphasis in the text",
		"The <company> tag identifies the organization",
		"Price range: <$100 to >$500",
		"Temperature: <0°C expected tonight",
		"Performance was >90% this quarter",

		// Common coding terms in documentation
		"The eval function assesses performance",
		"System command center is located downtown",
		"Execute the plan as directed",
		"Process the order within 24 hours",
		"Shell of the building was completed",

		// Mathematical and scientific
		"The equation is 1+1=2",
		"Calculate 5*10 for the total",
		"Ratio is approximately 1:1",
		"The formula: (a+b)*c",
		"Percentage: 50% off selected items",

		// Punctuation heavy but legitimate
		"What's your name?",
		"That's amazing!!!",
		"Really??? I can't believe it!",
		"Email: john.doe@example.com",
		"Time: 10:30 AM - 5:00 PM",
		"Phone: (555) 123-4567",
		"Reference #: ABC-12345",
	}
}

// getFormData returns realistic form input that should be allowed
func getFormData() []string {
	return []string{
		// Names with special characters
		"O'Brien",
		"McDonald's",
		"José García",
		"François Müller",
		"Sørensen",
		"Björk",
		"Łukasz Kowalski",
		"Çelik",
		"Đorđević",
		"Mary-Jane Watson",
		"John Smith Jr.",
		"Dr. Sarah Connor",
		"Ms. Anne-Marie",
		"Mr. Lee & Mrs. Lee",

		// Addresses
		"123 Main Street, Apt #4B",
		"Suite 500, 1st Floor",
		"P.O. Box 12345",
		"1/2 Maple Avenue",
		"Building A, Unit 101",
		"Corner of 5th & Main",
		"Near O'Hare Airport",

		// Common form fields
		"user@example.com",
		"john.doe+newsletter@company.org",
		"support@company.co.uk",
		"+1 (555) 123-4567",
		"+44 20 7946 0958",
		"https://www.example.com",
		"http://localhost:3000",
		"ftp://files.company.com",

		// Passwords (patterns, not real)
		"MyP@ssw0rd!",
		"Secure#123",
		"User$Name%2024",

		// Bio/description fields
		"I'm a software developer with 10+ years of experience",
		"Looking for opportunities in AI/ML",
		"Passionate about: coding, music & travel",
		"Skills: Python, JavaScript, SQL, etc.",
		"Contact me at: email@domain.com or call (555) 123-4567",

		// Feedback/comments
		"Great product! 5/5 stars",
		"Works as expected - would recommend",
		"Q: Does this work with Windows? A: Yes!",
		"Pro tip: use the search function",
		"Note: prices subject to change",
	}
}

// getAPIPayloads returns legitimate API request content
func getAPIPayloads() []string {
	return []string{
		// GraphQL-like queries (benign)
		`{"query": "{ user { name email } }"}`,
		`{"operationName": "GetUser", "variables": {"id": 123}}`,
		`{"data": {"users": [{"id": 1, "name": "John"}]}}`,

		// Common JSON payloads
		`{"username": "john_doe", "email": "john@example.com"}`,
		`{"page": 1, "limit": 20, "sort": "created_at"}`,
		`{"filter": {"status": "active", "type": "premium"}}`,
		`{"items": [{"id": 1, "qty": 2}, {"id": 2, "qty": 1}]}`,
		`{"search": "product name", "category": "electronics"}`,
		`{"date_from": "2024-01-01", "date_to": "2024-12-31"}`,
		`{"enabled": true, "settings": {"theme": "dark"}}`,

		// Common array values
		`["apple", "banana", "orange"]`,
		`[1, 2, 3, 4, 5]`,
		`[{"id": 1}, {"id": 2}]`,

		// URLs in JSON
		`{"callback": "https://example.com/webhook"}`,
		`{"avatar": "https://cdn.example.com/images/user.jpg"}`,
		`{"links": {"self": "/api/users/1", "posts": "/api/users/1/posts"}}`,

		// Common API patterns
		`{"action": "update", "resource": "user", "id": 123}`,
		`{"method": "POST", "endpoint": "/api/data"}`,
		`{"version": "2.0", "format": "json"}`,
	}
}

// getTechnicalContent returns technical/developer content
func getTechnicalContent() []string {
	return []string{
		// Code snippets in documentation (benign)
		"Use console.log() for debugging",
		"The function returns Array.map() result",
		"Call api.get('/users') to fetch data",
		"Set environment variable: export PATH=$PATH:/usr/bin",
		"Run command: npm install package-name",
		"Configure with: config.set('key', 'value')",
		"The regex pattern: ^[a-zA-Z0-9]+$",
		"CSS selector: .class-name #id-name",
		"jQuery example: $(document).ready()",
		"React component: <Component prop={value} />",

		// Log-like content
		"[INFO] Application started successfully",
		"[DEBUG] Processing request id=123",
		"[ERROR] Connection timeout after 30s",
		"[WARN] Deprecated function called",
		"2024-01-15 10:30:45 - User logged in",

		// Stack trace-like (benign error messages)
		"Error at line 42 in file main.js",
		"TypeError: Cannot read property 'name' of undefined",
		"NullPointerException: object is null",
		"IndexOutOfBoundsException: index 5, size 3",

		// SQL in documentation context
		"Example query: SELECT name FROM users WHERE id = ?",
		"Insert data with: INSERT INTO table VALUES (...)",
		"Use prepared statements to prevent injection",
		"The LIKE operator: WHERE name LIKE 'J%'",
	}
}

// getInternationalNames returns names with international characters
func getInternationalNames() []string {
	return []string{
		// European names
		"Müller", "Schröder", "Größe",
		"Núñez", "García", "Fernández",
		"François", "Benoît", "Léa",
		"Søren", "Ørsted", "Åberg",
		"Władysław", "Żółkiewski", "Łódź",
		"Dvořák", "Háček", "Řezníček",

		// Middle Eastern
		"محمد", "أحمد", "فاطمة",
		"משה", "דוד", "שרה",

		// Asian names
		"田中", "山本", "鈴木",
		"王", "李", "张",
		"김", "이", "박",

		// Special character handling
		"Æthelstan",
		"Œuvre",
		"Ñoño",

		// Compound names
		"María-José",
		"Jean-Pierre",
		"Anna-Lena",
		"Karl-Heinz",
	}
}

// AddDynamicCorpus adds content extracted from target site
func (c *Corpus) AddDynamicCorpus(content []string) {
	// Filter out anything that looks like actual attacks
	filtered := make([]string, 0, len(content))
	for _, s := range content {
		if !looksLikeAttack(s) {
			filtered = append(filtered, s)
		}
	}
	c.sources["dynamic"] = filtered
}

// looksLikeAttack performs basic sanity check to avoid testing actual attacks
func looksLikeAttack(s string) bool {
	lower := strings.ToLower(s)

	// Obvious attack patterns to exclude
	attackPatterns := []string{
		"<script",
		"javascript:",
		"onerror=",
		"onload=",
		"' or '1'='1",
		"' or 1=1",
		"union select",
		"../../../",
		"..\\..\\",
		"; drop table",
		"; delete from",
		"exec(", "eval(",
		"cmd.exe", "/bin/sh",
		"passwd", "/etc/shadow",
	}

	for _, pattern := range attackPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}
