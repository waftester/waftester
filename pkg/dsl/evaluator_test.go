package dsl

import "testing"

func TestEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		expr string
		data *ResponseData
		want bool
	}{
		{
			name: "empty expression matches all",
			expr: "",
			data: &ResponseData{StatusCode: 200},
			want: true,
		},
		{
			name: "nil response returns false",
			expr: "status_code == 200",
			data: nil,
			want: false,
		},
		{
			name: "status 200 bypass",
			expr: "status_code == 200",
			data: &ResponseData{StatusCode: 200},
			want: true,
		},
		{
			name: "status 403 WAF block",
			expr: "status_code == 403",
			data: &ResponseData{StatusCode: 403},
			want: true,
		},
		{
			name: "status 403 no match on 200",
			expr: "status_code == 403",
			data: &ResponseData{StatusCode: 200},
			want: false,
		},
		{
			name: "body contains data exfiltration",
			expr: `contains(body, "admin")`,
			data: &ResponseData{Body: "Welcome admin panel"},
			want: true,
		},
		{
			name: "body contains no match",
			expr: `contains(body, "admin")`,
			data: &ResponseData{Body: "Access denied"},
			want: false,
		},
		{
			name: "body not contains exclude block pages",
			expr: `!contains(body, "blocked")`,
			data: &ResponseData{Body: "Welcome to the site"},
			want: true,
		},
		{
			name: "body not contains WAF block page",
			expr: `!contains(body, "blocked")`,
			data: &ResponseData{Body: "Request blocked by WAF"},
			want: false,
		},
		{
			name: "header WAF pass via content_type",
			expr: `content_type == "text/html"`,
			data: &ResponseData{ContentType: "text/html"},
			want: true,
		},
		{
			name: "content_length filter empty block pages",
			expr: "content_length > 500",
			data: &ResponseData{ContentLength: 1024},
			want: true,
		},
		{
			name: "content_length small block page",
			expr: "content_length > 500",
			data: &ResponseData{ContentLength: 42},
			want: false,
		},
		{
			name: "regex injection output",
			expr: `matches(body, "user[0-9]+")`,
			data: &ResponseData{Body: "Injected: user42 found"},
			want: true,
		},
		{
			name: "regex no match",
			expr: `matches(body, "user[0-9]+")`,
			data: &ResponseData{Body: "No data found"},
			want: false,
		},
		{
			name: "compound AND multi-condition",
			expr: "status_code == 200 && content_length > 100",
			data: &ResponseData{StatusCode: 200, ContentLength: 500},
			want: true,
		},
		{
			name: "compound AND partial fail",
			expr: "status_code == 200 && content_length > 100",
			data: &ResponseData{StatusCode: 200, ContentLength: 50},
			want: false,
		},
		{
			name: "compound OR multiple success codes",
			expr: "status_code == 200 || status_code == 302",
			data: &ResponseData{StatusCode: 302},
			want: true,
		},
		{
			name: "compound OR neither match",
			expr: "status_code == 200 || status_code == 302",
			data: &ResponseData{StatusCode: 403},
			want: false,
		},
		{
			name: "invalid expression",
			expr: "!!!",
			data: &ResponseData{StatusCode: 200},
			want: false,
		},
		{
			name: "empty body contains",
			expr: `contains(body, "x")`,
			data: &ResponseData{Body: ""},
			want: false,
		},
		{
			name: "hasPrefix server",
			expr: `hasPrefix(server, "nginx")`,
			data: &ResponseData{Server: "nginx/1.24"},
			want: true,
		},
		{
			name: "hasSuffix host",
			expr: `hasSuffix(host, ".com")`,
			data: &ResponseData{Host: "example.com"},
			want: true,
		},
		{
			name: "len body check",
			expr: "len(body) > 10",
			data: &ResponseData{Body: "short"},
			want: false,
		},
		{
			name: "len body check passes",
			expr: "len(body) > 3",
			data: &ResponseData{Body: "a longer response body"},
			want: true,
		},
		{
			name: "status not equal",
			expr: "status_code != 403",
			data: &ResponseData{StatusCode: 200},
			want: true,
		},
		{
			name: "status less than",
			expr: "status_code < 400",
			data: &ResponseData{StatusCode: 200},
			want: true,
		},
		{
			name: "status greater equal",
			expr: "status_code >= 500",
			data: &ResponseData{StatusCode: 503},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Evaluate(tt.expr, tt.data)
			if got != tt.want {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}
