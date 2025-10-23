package secrets

import (
	"context"
	"errors"
	"strings"

	"github.com/RowanDark/0xgen/internal/logging"
	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the SecretsBroker gRPC service.
type Server struct {
	pb.UnimplementedSecretsBrokerServer
	manager *Manager
	audit   *logging.AuditLogger
}

// ServerOption configures the server.
type ServerOption func(*Server)

// WithServerAuditLogger overrides the audit logger used by the server.
func WithServerAuditLogger(logger *logging.AuditLogger) ServerOption {
	return func(s *Server) {
		if logger != nil {
			s.audit = logger
		}
	}
}

// NewServer constructs a secrets broker backed by the provided manager.
func NewServer(manager *Manager, opts ...ServerOption) *Server {
	if manager == nil {
		manager = NewManager(nil)
	}
	srv := &Server{
		manager: manager,
		audit:   logging.MustNewAuditLogger("secrets_broker"),
	}
	for _, opt := range opts {
		opt(srv)
	}
	return srv
}

// GetSecret resolves the requested secret when authorised by the provided token.
func (s *Server) GetSecret(ctx context.Context, req *pb.SecretAccessRequest) (*pb.SecretAccessResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	plugin := strings.TrimSpace(req.GetPluginName())
	token := strings.TrimSpace(req.GetToken())
	scope := strings.TrimSpace(req.GetScopeId())
	name := strings.TrimSpace(req.GetSecretName())
	if plugin == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	if token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if scope == "" {
		return nil, status.Error(codes.InvalidArgument, "scope_id is required")
	}
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_name is required")
	}

	value, err := s.manager.Resolve(token, plugin, scope, name)
	if err != nil {
		return nil, s.handleResolveError(plugin, name, err)
	}
	s.emit(logging.AuditEvent{
		EventType: logging.EventSecretsAccess,
		Decision:  logging.DecisionAllow,
		PluginID:  plugin,
		Metadata: map[string]any{
			"secret_name": name,
		},
	})
	return &pb.SecretAccessResponse{Value: value}, nil
}

func (s *Server) handleResolveError(plugin, name string, err error) error {
	var code codes.Code
	switch {
	case errors.Is(err, ErrTokenNotRecognised),
		errors.Is(err, ErrTokenExpired),
		errors.Is(err, ErrTokenRevoked),
		errors.Is(err, ErrTokenPluginMismatch),
		errors.Is(err, ErrTokenScopeMismatch),
		errors.Is(err, ErrSecretNotGranted),
		errors.Is(err, ErrPluginRequired),
		errors.Is(err, ErrScopeRequired),
		errors.Is(err, ErrSecretRequired):
		code = codes.PermissionDenied
	default:
		code = codes.Internal
	}
	s.emit(logging.AuditEvent{
		EventType: logging.EventSecretsDenied,
		Decision:  logging.DecisionDeny,
		PluginID:  plugin,
		Reason:    err.Error(),
		Metadata: map[string]any{
			"secret_name": name,
		},
	})
	if code == codes.Internal {
		return status.Error(code, "resolve secret")
	}
	return status.Error(code, err.Error())
}

func (s *Server) emit(event logging.AuditEvent) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Emit(event)
}
