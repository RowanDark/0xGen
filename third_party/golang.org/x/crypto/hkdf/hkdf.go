package hkdf

import (
	"crypto/hmac"
	"hash"
	"io"
)

// Extract generates a pseudorandom key from secret and salt.
func Extract(hash func() hash.Hash, secret, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, hash().Size())
	}
	h := hmac.New(hash, salt)
	h.Write(secret)
	return h.Sum(nil)
}

// Expand returns a Reader providing an HKDF stream using the given hash,
// pseudorandom key, and context info.
func Expand(hash func() hash.Hash, pseudorandomKey, info []byte) io.Reader {
	key := make([]byte, len(pseudorandomKey))
	copy(key, pseudorandomKey)
	ctx := make([]byte, len(info))
	copy(ctx, info)
	return &expander{
		hash: hash,
		prk:  key,
		info: ctx,
	}
}

type expander struct {
	hash func() hash.Hash
	prk  []byte
	info []byte
	buf  []byte
	off  int
	ctr  byte
}

func (e *expander) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var n int
	for len(p) > 0 {
		if e.off == len(e.buf) {
			if err := e.next(); err != nil {
				if n == 0 {
					return 0, err
				}
				return n, err
			}
		}
		copied := copy(p, e.buf[e.off:])
		n += copied
		e.off += copied
		p = p[copied:]
	}
	return n, nil
}

func (e *expander) next() error {
	if e.ctr == 255 {
		return io.EOF
	}
	e.ctr++
	mac := hmac.New(e.hash, e.prk)
	mac.Write(e.buf[:e.off])
	mac.Write(e.info)
	mac.Write([]byte{e.ctr})
	e.buf = mac.Sum(e.buf[:0])
	e.off = 0
	return nil
}

// New returns a Reader that first derives a pseudorandom key using Extract
// and then expands it using Expand.
func New(hash func() hash.Hash, secret, salt, info []byte) io.Reader {
	return Expand(hash, Extract(hash, secret, salt), info)
}

// Key derives a key of the requested length using Extract and Expand.
func Key(hash func() hash.Hash, secret, salt []byte, info string, length int) ([]byte, error) {
	r := Expand(hash, Extract(hash, secret, salt), []byte(info))
	key := make([]byte, length)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
