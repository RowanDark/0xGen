package bus

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"

	"github.com/RowanDark/Glyph/internal/findings"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type fuzzStream struct {
	events []*pb.PluginEvent
	index  int
	ctx    context.Context
}

func (s *fuzzStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *fuzzStream) SetHeader(metadata.MD) error  { return nil }
func (s *fuzzStream) SendHeader(metadata.MD) error { return nil }
func (s *fuzzStream) SetTrailer(metadata.MD)       {}
func (s *fuzzStream) Send(event *pb.HostEvent) error {
	// Discard events; the fuzzer only checks for panics.
	_ = event
	return nil
}

func (s *fuzzStream) Recv() (*pb.PluginEvent, error) {
	if s.index >= len(s.events) {
		return nil, io.EOF
	}
	evt := s.events[s.index]
	s.index++
	if evt == nil {
		return nil, io.EOF
	}
	return evt, nil
}

func (s *fuzzStream) SendMsg(interface{}) error { return nil }
func (s *fuzzStream) RecvMsg(interface{}) error { return io.EOF }

func FuzzPluginRPCFraming(f *testing.F) {
	hello := &pb.PluginEvent{
		Event: &pb.PluginEvent_Hello{Hello: &pb.PluginHello{
			AuthToken:       "token",
			PluginName:      "sample",
			Pid:             42,
			CapabilityToken: "grant",
			Capabilities:    []string{CapEmitFindings},
			Subscriptions:   []string{"FLOW_RESPONSE"},
		}},
	}
	finding := &pb.PluginEvent{
		Event: &pb.PluginEvent_Finding{Finding: &pb.Finding{
			Type:    "demo",
			Message: "demo",
		}},
	}
	f.Add(encodeEvents(hello))
	f.Add(encodeEvents(hello, finding))
	f.Add([]byte{0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		events := decodeEvents(data)
		srv := NewServer("token", findings.NewBus())

		authStream := &fuzzStream{events: events}
		_, _ = srv.authenticate(authStream)

		recvStream := &fuzzStream{events: events}
		pluginConn := &plugin{
			eventChan:    make(chan *pb.HostEvent, 1),
			capabilities: map[string]struct{}{CapEmitFindings: {}},
		}
		_ = srv.receiveEvents(recvStream, pluginConn, "fuzz-plugin")
	})
}

func encodeEvents(events ...*pb.PluginEvent) []byte {
	buf := &bytes.Buffer{}
	for _, evt := range events {
		if evt == nil {
			continue
		}
		payload, err := proto.Marshal(evt)
		if err != nil {
			continue
		}
		if len(payload) > 0xFFFF {
			payload = payload[:0xFFFF]
		}
		_ = binary.Write(buf, binary.LittleEndian, uint16(len(payload)))
		buf.Write(payload)
	}
	return buf.Bytes()
}

func decodeEvents(data []byte) []*pb.PluginEvent {
	events := []*pb.PluginEvent{}
	for len(data) >= 2 {
		frameLen := int(binary.LittleEndian.Uint16(data[:2]))
		data = data[2:]
		if frameLen == 0 {
			continue
		}
		if frameLen > len(data) {
			break
		}
		frame := data[:frameLen]
		data = data[frameLen:]
		var evt pb.PluginEvent
		if err := proto.Unmarshal(frame, &evt); err != nil {
			continue
		}
		events = append(events, &evt)
	}
	return events
}
