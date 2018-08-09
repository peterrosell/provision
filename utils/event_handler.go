package utils

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/gin-gonic/gin"
)

type PubFunc func(start, end time.Time, reqSz, resSz int64, status, adddres, url string)

type PubGin struct {
	pub PubFunc
}

// PubGin - publish stats
func NewPubGin(l logger.Logger, subsystem string, pub PubFunc) *PubGin {
	return &PubGin{pub: pub}
}

func (p *PubGin) HandlerGinFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		reqSz := int64(computeApproximateRequestSize(c.Request))

		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		end := time.Now()
		resSz := int64(c.Writer.Size())

		p.pub(start, end, reqSz, resSz, status, c.Request.Host, c.Request.URL.String())
	}
}

func (p *PubGin) Handler(responder http.Handler) http.Handler {
	return &PubGinResponder{p: p, responder: responder}
}

type PubGinResponder struct {
	p         *PubGin
	responder http.Handler
}

func (pr *PubGinResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqSz := int64(computeApproximateRequestSize(r))

	w2 := &sizeStatusRecorder{ResponseWriter: w, size: noWritten}
	pr.responder.ServeHTTP(w2, r)

	status := strconv.Itoa(w2.status)
	end := time.Now()
	resSz := int64(w2.size)

	c := &gin.Context{Request: r, Params: []gin.Param{}}
	hostIndex := strings.LastIndex(r.RemoteAddr, ":")
	pr.p.pub(start, end, reqSz, resSz, status, r.RemoteAddr[:hostIndex], c.Request.URL.String())
}
