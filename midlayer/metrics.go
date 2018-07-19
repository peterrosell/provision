package midlayer

import (
	"net"
	"net/http"

	"github.com/digitalrebar/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func ServeMetrics(listenAt string, logger logger.Logger) (*http.Server, error) {
	conn, err := net.Listen("tcp", listenAt)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	svr := &http.Server{
		Addr:    listenAt,
		Handler: mux,
	}
	go func() {
		if err := svr.Serve(conn); err != nil {
			if err != http.ErrServerClosed {
				logger.Fatalf("Static HTTP server error %v", err)
			}
		}
	}()
	return svr, nil
}
