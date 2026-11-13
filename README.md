# x-forwarded-for-hop-counter-tools

Parses an `X-Forwarded-For` header, trims a trusted number of proxy hops from the right, and returns the originating client IP.

```go
package main

import (
	"fmt"

	xff "x-forwarded-for-hop-counter-tools"
)

func main() {
	client, err := xff.ParseXForwardedFor("198.51.100.4, 10.0.0.1", 1)
	if err != nil {
		panic(err)
	}
	fmt.Println(client) // 198.51.100.4
}
```

## Why this exists

When a request arrives through a chain of proxies, `X-Forwarded-For` is a comma-separated list that grows at the right end as each proxy appends the address it received the connection from. The address of the actual client is therefore `len(entries) - trustedHops - 1`, where `trustedHops` is the number of proxies you control. The trade-off is that the library trusts the caller to supply the correct hop count: there is no way to verify a proxy chain from the header alone, so a wrong count silently returns the wrong address. Callers who cannot pin the hop count should not use this library as an authentication primitive.

## API

- `ParseXForwardedFor(header string, trustedHops int) (string, error)` — returns the client IP after discarding `trustedHops` entries from the right. Entries are trimmed of surrounding whitespace and empty entries are skipped. Valid IPs are normalised with `net.ParseIP`; entries that are not valid IPs are returned as their trimmed raw text. Returns `ErrInvalidHopCount` for a negative hop count and `ErrNoClientIP` when no usable entry remains.
- `ClientIP(header string, trustedHops int) string` — convenience wrapper that returns the empty string on any error.
- `ErrInvalidHopCount`, `ErrNoClientIP` — sentinel errors for `errors.Is`.

## The awkward edge

A header whose entries are all consumed by `trustedHops` is not an error in the header; it is a configuration error in the caller. The library reports `ErrNoClientIP` rather than guessing, because returning the closest proxy address would be indistinguishable from a real client address.
