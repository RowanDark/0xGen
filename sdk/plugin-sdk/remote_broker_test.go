package pluginsdk

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeSecretsClient struct {
	req  *pb.SecretAccessRequest
	resp *pb.SecretAccessResponse
	err  error
}

func (f *fakeSecretsClient) GetSecret(ctx context.Context, in *pb.SecretAccessRequest, opts ...grpc.CallOption) (*pb.SecretAccessResponse, error) {
	f.req = in
	return f.resp, f.err
}

func TestRemoteSecretsRequiresToken(t *testing.T) {
	if secrets := newRemoteSecrets("seer", "", "scope", &fakeSecretsClient{}); secrets != nil {
		t.Fatalf("expected nil secrets broker when token missing")
	}
	if secrets := newRemoteSecrets("seer", "token", "", &fakeSecretsClient{}); secrets != nil {
		t.Fatalf("expected nil secrets broker when scope missing")
	}
	if secrets := newRemoteSecrets("seer", "token", "scope", nil); secrets != nil {
		t.Fatalf("expected nil secrets broker when client missing")
	}
}

func TestRemoteSecretsSuccess(t *testing.T) {
	fake := &fakeSecretsClient{resp: &pb.SecretAccessResponse{Value: "super"}}
	secrets := newRemoteSecrets(" seer ", " token ", " scope ", fake)
	if secrets == nil {
		t.Fatalf("expected remote secrets instance")
	}
	value, err := secrets.Get(context.Background(), " api_token ")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if value != "super" {
		t.Fatalf("unexpected secret value: %s", value)
	}
	if fake.req == nil {
		t.Fatalf("expected request to be captured")
	}
	if got := fake.req.GetPluginName(); got != "seer" {
		t.Fatalf("unexpected plugin name: %s", got)
	}
	if got := fake.req.GetSecretName(); got != "api_token" {
		t.Fatalf("unexpected secret name: %s", got)
	}
	if got := fake.req.GetToken(); got != "token" {
		t.Fatalf("unexpected token: %s", got)
	}
	if got := fake.req.GetScopeId(); got != "scope" {
		t.Fatalf("unexpected scope: %s", got)
	}
}

func TestRemoteSecretsErrorMapping(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantErr error
		check   func(error) bool
	}{
		{
			name:    "not_found",
			err:     status.Error(codes.NotFound, "secret missing"),
			wantErr: ErrNotFound,
		},
		{
			name: "permission_denied",
			err:  status.Error(codes.PermissionDenied, "not granted"),
			check: func(err error) bool {
				return strings.Contains(err.Error(), "denied")
			},
		},
		{
			name: "internal",
			err:  status.Error(codes.Internal, "boom"),
			check: func(err error) bool {
				return strings.Contains(err.Error(), "boom")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSecretsClient{err: tc.err}
			secrets := newRemoteSecrets("seer", "token", "scope", fake)
			if secrets == nil {
				t.Fatalf("expected remote secrets instance")
			}
			_, err := secrets.Get(context.Background(), "api_token")
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error")
			}
			if tc.check != nil && !tc.check(err) {
				t.Fatalf("error did not match expectation: %v", err)
			}
		})
	}
}

func TestRemoteSecretsValidatesName(t *testing.T) {
	fake := &fakeSecretsClient{}
	secrets := newRemoteSecrets("seer", "token", "scope", fake)
	if secrets == nil {
		t.Fatalf("expected remote secrets instance")
	}
	if _, err := secrets.Get(context.Background(), "   "); err == nil {
		t.Fatalf("expected error for empty secret name")
	}
}
