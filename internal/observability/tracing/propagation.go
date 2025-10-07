package tracing

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/metadata"
)

const traceparentHeader = "traceparent"

// ParseTraceParent converts a W3C traceparent header into a span context.
func ParseTraceParent(header string) (SpanContext, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return SpanContext{}, fmt.Errorf("empty traceparent")
	}
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return SpanContext{}, fmt.Errorf("invalid traceparent format")
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]
	if len(version) != 2 || len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 {
		return SpanContext{}, fmt.Errorf("malformed traceparent components")
	}
	if _, err := hex.DecodeString(traceID); err != nil {
		return SpanContext{}, fmt.Errorf("invalid trace id: %w", err)
	}
	if _, err := hex.DecodeString(spanID); err != nil {
		return SpanContext{}, fmt.Errorf("invalid span id: %w", err)
	}
	sampled := strings.HasSuffix(flags, "1")
	return SpanContext{TraceID: traceID, SpanID: spanID, Sampled: sampled}, nil
}

// FormatTraceParent renders sc into the W3C traceparent representation.
func FormatTraceParent(sc SpanContext) string {
	if !sc.Valid() {
		return ""
	}
	flags := "00"
	if sc.Sampled {
		flags = "01"
	}
	return fmt.Sprintf("00-%s-%s-%s", sc.TraceID, sc.SpanID, flags)
}

// ExtractFromMetadata obtains the span context from gRPC metadata when available.
func ExtractFromMetadata(md metadata.MD) SpanContext {
	if md == nil {
		return SpanContext{}
	}
	values := md.Get(traceparentHeader)
	for _, header := range values {
		sc, err := ParseTraceParent(header)
		if err == nil {
			return sc
		}
	}
	return SpanContext{}
}

// InjectHTTP propagates the current span context onto the outbound request.
func InjectHTTP(req *http.Request) {
	if req == nil {
		return
	}
	sc := SpanContextFromContext(req.Context())
	if !sc.Valid() {
		return
	}
	req.Header.Set(traceparentHeader, FormatTraceParent(sc))
}

// ContextWithMetadataSpan extracts trace information from incoming metadata and attaches it to ctx.
func ContextWithMetadataSpan(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	sc := ExtractFromMetadata(md)
	if !sc.Valid() {
		return ctx
	}
	return WithSpanContext(ctx, sc)
}
