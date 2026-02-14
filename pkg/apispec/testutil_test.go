package apispec

// Shared test helpers for apispec tests. Not exported.

// newTestSpec creates a minimal Spec for test assertions.
func newTestSpec() *Spec {
	return &Spec{
		Format:    FormatOpenAPI3,
		Title:     "Test API",
		Version:   "1.0.0",
		Variables: make(map[string]Variable),
		Endpoints: []Endpoint{
			newTestEndpoint("GET", "/pets"),
			newTestEndpoint("POST", "/pets"),
			newTestEndpoint("GET", "/pets/{petId}"),
		},
		Servers: []Server{
			{URL: "https://api.example.com"},
		},
		Groups: []Group{
			{Name: "pets"},
		},
	}
}

// newTestEndpoint creates a minimal Endpoint for test assertions.
func newTestEndpoint(method, path string) Endpoint {
	return Endpoint{
		Method:         method,
		Path:           path,
		CorrelationTag: CorrelationTag(method, path),
		RequestBodies:  make(map[string]RequestBody),
		Responses:      make(map[string]Response),
	}
}

// newTestParameter creates a Parameter with common defaults.
func newTestParameter(name string, in Location) Parameter {
	return Parameter{
		Name: name,
		In:   in,
	}
}
