package midlayer

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/utils"
	"github.com/pin/tftp"
)

type TftpHandler struct {
	srv *tftp.Server
}

func (h *TftpHandler) Shutdown(ctx context.Context) error {
	h.srv.Shutdown()
	return nil
}

func OsUdpProtoCheck() string {
	if runtime.GOOS == "darwin" {
		return "udp4"
	}
	return "udp"
}

func ServeTftp(listen string, responder func(string, net.IP) (io.Reader, error),
	log logger.Logger, pubs *backend.Publishers) (Service, error) {
	a, err := net.ResolveUDPAddr(OsUdpProtoCheck(), listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(OsUdpProtoCheck(), a)
	if err != nil {
		return nil, err
	}

	p := utils.NewPromGin(log, "drp_tftp", nil)

	readHandler := func(filename string, rf io.ReaderFrom) error {
		start := time.Now()
		recorded := false
		method := "INFO"
		status := "CRASH"

		var local net.IP
		var remote net.UDPAddr
		l := log.Fork().SetPrincipal("tftp")
		t, outgoing := rf.(tftp.OutgoingTransfer)
		rpi, haveRPI := rf.(tftp.RequestPacketInfo)
		if outgoing && haveRPI {
			local = rpi.LocalIP()
		}
		if outgoing {
			method = "GET"
			remote = t.RemoteAddr()
		}
		if outgoing && haveRPI {
			backend.AddToCache(l, local, remote.IP)
		} else {
			l.Errorf("TFTP: Failed to get remote and local IP address information")
		}
		l.Debugf("TFTP: attempting to send %s", filename)
		defer func() {
			if r := recover(); r != nil {
				l.Errorf("TFTP: Recovered from panic:\n%v", r)
				if !recorded {
					elapsed := float64(time.Since(start)) / float64(time.Second)
					p.Observe("reqDur", elapsed)
					p.Observe("resSz", 0)
					p.CounterWithLabelValues("reqCnt", status, method, remote.IP.String(), filename).Inc()
				}
			}
		}()
		source, err := responder(filename, remote.IP)
		if err != nil {
			return err
		}
		if cl, ok := source.(io.ReadCloser); ok {
			defer cl.Close()
		}
		var size int64
		if outgoing {
			switch src := source.(type) {
			case *os.File:
				defer src.Close()
				if fi, err := src.Stat(); err == nil {
					size = fi.Size()
				}
			case backend.Sizer:
				size = src.Size()
			}
			t.SetSize(size)
			l.Debugf("TFTP: %s: size: %d", filename, size)
		}
		_, err = rf.ReadFrom(source)
		if err != nil {
			l.Infof("TFTP: %s: transfer error: %v", filename, err)
			status = "FAILED"
		} else {
			status = "SUCCESS"
		}
		recorded = true
		elapsed := float64(time.Since(start)) / float64(time.Second)
		p.Observe("reqDur", elapsed)
		p.Observe("resSz", float64(size))
		p.CounterWithLabelValues("reqCnt", status, method, remote.IP.String(), filename).Inc()

		data := &fileData{
			Start:        start,
			End:          time.Now(),
			RequestSize:  0,
			ResponseSize: size,
			Status:       status,
			Requestor:    remote.IP.String(),
			Url:          filename,
		}
		if err := pubs.Publish("tftp", "serve", filename, "tftp", data); err != nil {
			l.Errorf("Failed to publish event: %v", err)
		}

		return err
	}
	svr := tftp.NewServer(readHandler, nil)

	th := &TftpHandler{srv: svr}

	go svr.Serve(conn)

	return th, nil
}
