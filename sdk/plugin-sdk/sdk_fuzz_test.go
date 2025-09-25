package pluginsdk

import "testing"

func FuzzHeaderParse(f *testing.F) {
	seeds := [][]byte{
		[]byte("HTTP/1.1 200 OK\nContent-Type: text/plain\n\nhello"),
		[]byte("HTTP/1.1 204 No Content\n\n"),
		[]byte{},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseHTTPResponse(raw)
	})
}
