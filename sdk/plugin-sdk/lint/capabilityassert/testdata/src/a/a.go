package a

import (
    "context"
    "net"
    "net/http"
    "os"
)

func bad() {
    _, _ = net.Dial("tcp", "example.com:80") // want "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND"
    _, _ = net.DialTimeout("tcp", "example.com:80", 0) // want "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND"
    _, _ = http.Get("https://example.com") // want "use pluginsdk.UseNetwork with CAP_NET_OUTBOUND"
    _, _ = os.ReadFile("secret") // want "use pluginsdk.UseFilesystem with workspace capabilities"
}

func good(ctx context.Context, dialer func(context.Context) error) {
    _ = dialer(ctx)
}
