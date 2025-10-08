package proxy

import "net/http"

func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	meta := connectionMetadataFromContext(r.Context())
	scheme := ""
	host := ""
	clientAddr := r.RemoteAddr
	if meta != nil {
		scheme = meta.scheme
		if meta.host != "" {
			host = meta.host
		}
		if meta.clientAddr != "" {
			clientAddr = meta.clientAddr
		}
	}

	p.serveProxyRequest(w, r, scheme, host, clientAddr, false, false, false)
}
