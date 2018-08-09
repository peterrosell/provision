package midlayer

import (
	"net"
	"net/http"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/utils"
)

type fileData struct {
	Start        time.Time
	End          time.Time
	RequestSize  int64
	ResponseSize int64
	Status       string
	Requestor    string
	Url          string
}

func ServeStatic(listenAt string, responder http.Handler, logger logger.Logger, pubs *backend.Publishers) (*http.Server, error) {
	conn, err := net.Listen("tcp", listenAt)
	if err != nil {
		return nil, err
	}

	p := utils.NewPromGin(logger, "drp_static", nil)
	r := p.Handler(responder)

	pub := utils.NewPubGin(logger, "static", func(start, end time.Time, reqSz, resSz int64, status, address, url string) {
		data := &fileData{
			Start:        start,
			End:          end,
			RequestSize:  reqSz,
			ResponseSize: resSz,
			Status:       status,
			Requestor:    address,
			Url:          url,
		}
		if err := pubs.Publish("static", "serve", url, "static", data); err != nil {
			logger.Errorf("Failed to publish event: %v", err)
		}
	})
	r = pub.Handler(r)

	svr := &http.Server{
		Addr:    listenAt,
		Handler: r,
		ConnState: func(n net.Conn, cs http.ConnState) {
			if cs == http.StateActive {
				laddr, lok := n.LocalAddr().(*net.TCPAddr)
				raddr, rok := n.RemoteAddr().(*net.TCPAddr)
				if lok && rok {
					l := logger.Fork().SetPrincipal("http")
					backend.AddToCache(l, laddr.IP, raddr.IP)
				}
			}
		},
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
