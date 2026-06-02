package server

import "testing"

func TestNormalizeRoute(t *testing.T) {
	cases := map[string]string{
		"/task":        "/task",
		"/logs/stream": "/logs/stream",
		"/metrics":     "/metrics",
		"/healthz":     "/healthz",
		"/unknown":     "other",
		"/task/../etc": "other",
		"/task?x=1":    "other", // raw path with query won't match; URL.Path is pre-stripped in practice
		"":             "other",
	}
	for in, want := range cases {
		if got := normalizeRoute(in); got != want {
			t.Errorf("normalizeRoute(%q) = %q, want %q", in, got, want)
		}
	}
}
