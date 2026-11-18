package vulnrecency

import (
	"testing"
	"time"
)

type row struct {
	id string
	t  time.Time
}

func ids(rs []row) string {
	s := ""
	for _, r := range rs {
		s += r.id
	}
	return s
}

func TestKeep(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	old, fresh := now.Add(-30*24*time.Hour), now.Add(-2*time.Hour)
	rows := []row{{"a", old}, {"b", old}, {"c", old}, {"d", fresh}, {"e", time.Time{}}, {"f", fresh}}
	get := func(r row) time.Time { return r.t }

	if got := ids(Keep(rows, 3, 0, now, get)); got != "abc" {
		t.Fatalf("days=0: got %q, want plain prefix abc", got)
	}
	if got := ids(Keep(rows, 3, 7, now, get)); got != "adf" {
		t.Fatalf("days=7: got %q, want recent d,f kept plus top old a, in original order", got)
	}
	if got := ids(Keep(rows, 1, 7, now, get)); got != "d" {
		t.Fatalf("limit below recent count: got %q, want first recent only", got)
	}
	if got := ids(Keep(rows, 10, 7, now, get)); got != "abcdef" {
		t.Fatalf("under limit: got %q, want everything", got)
	}
}

func TestClamp(t *testing.T) {
	for in, want := range map[int]int{-1: 0, 0: 0, 7: 7, 500: MaxDays} {
		if got := Clamp(in); got != want {
			t.Errorf("Clamp(%d) = %d, want %d", in, got, want)
		}
	}
}
