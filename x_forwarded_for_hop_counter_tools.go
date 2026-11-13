// Package xforwardedforhopcountertools parses X-Forwarded-For headers and
// trims them to a trusted proxy hop count to recover the originating client IP.
//
// The package makes one deliberate decision: the rightmost entry in an
// X-Forwarded-For list is the closest proxy to the server, so a trusted hop
// count is consumed from the right. This is the only interpretation the
// implementation supports.
package xforwardedforhopcountertools

import (
	"errors"
	"net"
	"strings"
)

// ErrInvalidHopCount is returned when the trusted hop count is negative.
var ErrInvalidHopCount = errors.New("x-forwarded-for hop count must not be negative")

// ErrNoClientIP is returned when there are no usable entries after trimming.
var ErrNoClientIP = errors.New("x-forwarded-for contains no usable client IP")

// ParseXForwardedFor parses an X-Forwarded-For header value and returns the
// originating client IP after discarding trustedHops entries from the right.
//
// Entries are trimmed of surrounding whitespace and empty entries are skipped.
// The returned IP is normalised through net.ParseIP so that equivalent forms
// (for example IPv6 addresses with a zone) compare consistently. If the
// resulting entry is not a valid IP address, the raw trimmed entry is returned
// so that callers can still inspect what the header contained.
func ParseXForwardedFor(header string, trustedHops int) (string, error) {
	if trustedHops < 0 {
		return "", ErrInvalidHopCount
	}

	entries := splitEntries(header)
	if len(entries) == 0 {
		return "", ErrNoClientIP
	}

	// Consume trusted hops from the right, because the rightmost entry is the
	// proxy closest to this server.
	remaining := len(entries) - trustedHops
	if remaining <= 0 {
		return "", ErrNoClientIP
	}

	client := entries[remaining-1]
	if ip := net.ParseIP(client); ip != nil {
		return ip.String(), nil
	}
	return client, nil
}

// ClientIP is a convenience wrapper around ParseXForwardedFor for callers that
// already know the hop count is valid.
func ClientIP(header string, trustedHops int) string {
	ip, err := ParseXForwardedFor(header, trustedHops)
	if err != nil {
		return ""
	}
	return ip
}

// splitEntries normalises the header into a slice of non-empty, trimmed
// entries. Splitting on commas is the only separator defined by the de-facto
// X-Forwarded-For format.
func splitEntries(header string) []string {
	parts := strings.Split(header, ",")
	entries := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			entries = append(entries, trimmed)
		}
	}
	return entries
}
