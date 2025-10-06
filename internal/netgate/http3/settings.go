// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.24

package http3

const (
	// https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1
	settingsMaxFieldSectionSize = 0x06

	// https://www.rfc-editor.org/rfc/rfc9204.html#section-5
	settingsQPACKMaxTableCapacity = 0x01
	settingsQPACKBlockedStreams   = 0x07
)

// writeSettings writes a complete SETTINGS frame.
// Its parameter is a list of alternating setting types and values.
func (st *stream) writeSettings(settings ...int64) {
	var size int64
	for _, s := range settings {
		// Settings values that don't fit in a QUIC varint ([0,2^62)) will panic here.
		size += sizeVarint(uint64(s))
	}
	st.writeVarint(int64(frameTypeSettings))
	st.writeVarint(size)
	for _, s := range settings {
		st.writeVarint(s)
	}
}

func sizeVarint(v uint64) int64 {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	case v < 1<<62:
		return 8
	default:
		panic("http3: value exceeds QUIC varint range")
	}
}

// readSettings reads a complete SETTINGS frame, including the frame header.
func (st *stream) readSettings(f func(settingType, value int64) error) error {
	frameType, err := st.readFrameHeader()
	if err != nil || frameType != frameTypeSettings {
		return &connectionError{
			code:    errH3MissingSettings,
			message: "settings not sent on control stream",
		}
	}
	for st.lim > 0 {
		settingsType, err := st.readVarint()
		if err != nil {
			return err
		}
		settingsValue, err := st.readVarint()
		if err != nil {
			return err
		}

		// Use of HTTP/2 settings where there is no corresponding HTTP/3 setting
		// is an error.
		// https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1-5
		switch settingsType {
		case 0x02, 0x03, 0x04, 0x05:
			return &connectionError{
				code:    errH3SettingsError,
				message: "use of reserved setting",
			}
		}

		if err := f(settingsType, settingsValue); err != nil {
			return err
		}
	}
	return st.endFrame()
}
