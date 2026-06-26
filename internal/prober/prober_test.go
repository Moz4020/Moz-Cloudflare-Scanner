package prober

import "testing"

func TestParseColoCDN(t *testing.T) {
	body := "fl=1\ncolo=FRA\nhttp=http/2\n"
	if got := parseColoCDN(body); got != "FRA" {
		t.Fatalf("parseColoCDN = %q, want FRA", got)
	}
}

func TestParseColoRay(t *testing.T) {
	if got := parseColoRay("8790abcd-FRA"); got != "FRA" {
		t.Fatalf("parseColoRay = %q, want FRA", got)
	}
}
