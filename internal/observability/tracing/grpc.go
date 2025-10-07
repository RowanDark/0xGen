package tracing

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// UnaryServerInterceptor instruments unary gRPC handlers with tracing spans.
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		ctx = ContextWithMetadataSpan(ctx)
		attrs := map[string]any{"rpc.system": "grpc", "rpc.grpc.type": "unary"}
		service, method := splitMethod(info.FullMethod)
		if service != "" {
			attrs["rpc.service"] = service
		}
		if method != "" {
			attrs["rpc.method"] = method
		}
		ctx, span := StartSpan(ctx, info.FullMethod, WithSpanKind(SpanKindServer), WithAttributes(attrs))
		resp, err := handler(ctx, req)
		if err != nil {
			span.RecordError(err)
			span.End()
			return resp, err
		}
		span.EndWithStatus(StatusOK, "")
		return resp, nil
	}
}

// StreamServerInterceptor instruments streaming gRPC handlers with tracing spans.
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := ContextWithMetadataSpan(ss.Context())
		attrs := map[string]any{"rpc.system": "grpc", "rpc.grpc.type": streamType(info)}
		service, method := splitMethod(info.FullMethod)
		if service != "" {
			attrs["rpc.service"] = service
		}
		if method != "" {
			attrs["rpc.method"] = method
		}
		ctx, span := StartSpan(ctx, info.FullMethod, WithSpanKind(SpanKindServer), WithAttributes(attrs))
		wrapped := &serverStream{ServerStream: ss, ctx: ctx}
		err := handler(srv, wrapped)
		if err != nil {
			span.RecordError(err)
			span.End()
			return err
		}
		span.EndWithStatus(StatusOK, "")
		return nil
	}
}

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context { return s.ctx }

func splitMethod(full string) (string, string) {
	full = strings.TrimPrefix(full, "/")
	parts := strings.Split(full, "/")
	if len(parts) != 2 {
		return full, ""
	}
	return parts[0], parts[1]
}

func streamType(info *grpc.StreamServerInfo) string {
	switch {
	case info.IsClientStream && info.IsServerStream:
		return "bidi"
	case info.IsClientStream:
		return "client_stream"
	case info.IsServerStream:
		return "server_stream"
	default:
		return "unary"
	}
}

// InjectTraceParent appends the current span context to outgoing metadata.
func InjectTraceParent(ctx context.Context, md metadata.MD) metadata.MD {
	if md == nil {
		md = metadata.New(nil)
	}
	sc := SpanContextFromContext(ctx)
	if !sc.Valid() {
		return md
	}
	md.Set(traceparentHeader, FormatTraceParent(sc))
	return md
}
