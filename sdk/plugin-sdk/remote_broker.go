package pluginsdk

import (
	"context"
	"errors"
	"fmt"
	"strings"

	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type remoteBroker struct {
	secrets SecretsBroker
}

func newRemoteBroker(pluginName, secretsToken, secretsScope string, conn grpc.ClientConnInterface) Broker {
	rb := &remoteBroker{}
	if conn != nil {
		rb.secrets = newRemoteSecrets(pluginName, secretsToken, secretsScope, pb.NewSecretsBrokerClient(conn))
	}
	return rb
}

func (r *remoteBroker) Filesystem() FilesystemBroker { return nil }

func (r *remoteBroker) Network() NetworkBroker { return nil }

func (r *remoteBroker) Secrets() SecretsBroker { return r.secrets }

type secretsClient interface {
	GetSecret(ctx context.Context, in *pb.SecretAccessRequest, opts ...grpc.CallOption) (*pb.SecretAccessResponse, error)
}

func newRemoteSecrets(pluginName, token, scope string, client secretsClient) SecretsBroker {
	trimmedToken := strings.TrimSpace(token)
	trimmedScope := strings.TrimSpace(scope)
	if trimmedToken == "" || trimmedScope == "" || client == nil {
		return nil
	}
	return &remoteSecrets{
		pluginName: strings.TrimSpace(pluginName),
		token:      trimmedToken,
		scope:      trimmedScope,
		client:     client,
	}
}

type remoteSecrets struct {
	pluginName string
	token      string
	scope      string
	client     secretsClient
}

func (r *remoteSecrets) Get(ctx context.Context, name string) (string, error) {
	if r == nil || r.client == nil {
		return "", ErrBrokerUnavailable
	}
	secretName := strings.TrimSpace(name)
	if secretName == "" {
		return "", errors.New("secret name is required")
	}
	res, err := r.client.GetSecret(ctx, &pb.SecretAccessRequest{
		PluginName: r.pluginName,
		Token:      r.token,
		ScopeId:    r.scope,
		SecretName: secretName,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.NotFound:
				return "", ErrNotFound
			case codes.PermissionDenied:
				return "", fmt.Errorf("secrets broker denied access: %s", st.Message())
			default:
				return "", fmt.Errorf("secrets broker error: %s", st.Message())
			}
		}
		return "", err
	}
	return res.GetValue(), nil
}
