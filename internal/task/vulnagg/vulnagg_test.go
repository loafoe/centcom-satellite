package vulnagg

import "testing"

func TestMergeIsOrderIndependent(t *testing.T) {
	fixes := [][]string{{"NO", "YES", "NO"}, {"YES", "NO"}, {"NO", "PARTIAL"}, {"PARTIAL", "NO"}, {"", "NO"}, {"NO", ""}, {"PARTIAL", "YES"}}
	want := []string{"YES", "YES", "PARTIAL", "PARTIAL", "NO", "NO", "YES"}
	for i, seq := range fixes {
		got := ""
		for _, v := range seq {
			got = MergeFix(got, v)
		}
		if got != want[i] {
			t.Errorf("MergeFix%v = %q, want %q", seq, got, want[i])
		}
	}
	if MergeExploit(MergeExploit("", "YES"), "NO") != "YES" || MergeExploit(MergeExploit("", "NO"), "") != "NO" {
		t.Error("MergeExploit: YES must win, empty must not override")
	}
}
