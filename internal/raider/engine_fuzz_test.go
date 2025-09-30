package raider

import (
	"bufio"
	"context"
	"strings"
	"testing"
)

func FuzzBuildRequest(f *testing.F) {
	seeds := []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
		"POST http://example.com/upload HTTP/1.1\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"INVALID REQUEST",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		ctx := context.Background()
		req, _, err := buildRequest(ctx, raw)
		if err != nil {
			return
		}

		if req == nil {
			t.Fatalf("buildRequest returned nil request without error")
		}

		if req.Body == nil {
			return
		}

		reader := bufio.NewReader(req.Body)
		data, err := reader.ReadBytes(0)
		if err != nil && !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("unexpected body read error: %v", err)
		}
		_ = data
	})
}
