package xforwardedforhopcountertools

import (
	"errors"
	"testing"
)

func TestParseXForwardedForSingleEntry(t *testing.T) {
	got, err := ParseXForwardedFor("203.0.113.7", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "203.0.113.7"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseXForwardedForTrimsTrustedHops(t *testing.T) {
	// With one trusted proxy in front, the last entry is the proxy and the
	// first entry is the client.
	got, err := ParseXForwardedFor("198.51.100.4, 10.0.0.1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "198.51.100.4"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseXForwardedForMultipleHops(t *testing.T) {
	header := "192.0.2.10, 10.0.0.2, 10.0.0.3, 10.0.0.4"
	got, err := ParseXForwardedFor(header, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "10.0.0.2"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseXForwardedForWhitespaceAndEmptyEntries(t *testing.T) {
	header := "  203.0.113.9 ,, 10.0.0.1 ,"
	got, err := ParseXForwardedFor(header, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "203.0.113.9"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseXForwardedForIPv6Normalisation(t *testing.T) {
	// net.ParseIP normalises the IPv6 form, so the caller gets a canonical
	// string rather than the exact bytes from the header.
	got, err := ParseXForwardedFor("2001:0db8:0000:0000:0000:0000:0000:0001, 10.0.0.1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "2001:db8::1"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseXForwardedForNonIPEntryReturnedRaw(t *testing.T) {
	// Unknown tokens are preserved so the caller can decide what to do.
	got, err := ParseXForwardedFor("unknown, 10.0.0.1", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "unknown"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseXForwardedForNegativeHops(t *testing.T) {
	_, err := ParseXForwardedFor("203.0.113.7", -1)
	if !errors.Is(err, ErrInvalidHopCount) {
		t.Fatalf("got error %v, want ErrInvalidHopCount", err)
	}
}

func TestParseXForwardedForEmptyHeader(t *testing.T) {
	_, err := ParseXForwardedFor("", 0)
	if !errors.Is(err, ErrNoClientIP) {
		t.Fatalf("got error %v, want ErrNoClientIP", err)
	}
}

func TestParseXForwardedForAllEntriesConsumed(t *testing.T) {
	_, err := ParseXForwardedFor("203.0.113.7", 1)
	if !errors.Is(err, ErrNoClientIP) {
		t.Fatalf("got error %v, want ErrNoClientIP", err)
	}
}

func TestParseXForwardedForMoreHopsThanEntries(t *testing.T) {
	_, err := ParseXForwardedFor("203.0.113.7, 10.0.0.1", 5)
	if !errors.Is(err, ErrNoClientIP) {
		t.Fatalf("got error %v, want ErrNoClientIP", err)
	}
}

func TestClientIPConvenience(t *testing.T) {
	if got, want := ClientIP("198.51.100.4, 10.0.0.1", 1), "198.51.100.4"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := ClientIP("", 0); got != "" {
		t.Fatalf("got %q, want empty string", got)
	}
}
