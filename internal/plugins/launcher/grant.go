package launcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/plugins"
	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func requestCapabilityGrant(parent context.Context, addr, authToken string, manifest *plugins.Manifest) (string, error) {
	if manifest == nil {
		return "", errors.New("manifest is required")
	}
	dialCtx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "", fmt.Errorf("dial 0xgend: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	client := pb.NewPluginBusClient(conn)
	reqCtx, reqCancel := context.WithTimeout(parent, 5*time.Second)
	defer reqCancel()
	resp, err := client.GrantCapabilities(reqCtx, &pb.PluginCapabilityRequest{
		AuthToken:    authToken,
		PluginName:   manifest.Name,
		Capabilities: manifest.Capabilities,
	})
	if err != nil {
		return "", fmt.Errorf("grant capabilities: %w", err)
	}
	token := strings.TrimSpace(resp.GetCapabilityToken())
	if token == "" {
		return "", errors.New("received empty capability token")
	}
	return token, nil
}
