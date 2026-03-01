package httputil

// IsSuccess returns true for 2xx status codes.
func IsSuccess(code int) bool {
	return code >= 200 && code < 300
}

// IsSuccessOrRedirect returns true for 2xx and 3xx status codes.
func IsSuccessOrRedirect(code int) bool {
	return code >= 200 && code < 400
}
