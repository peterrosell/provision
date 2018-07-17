package utils

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/gin-gonic/gin"
)

var noWritten = -1
var defaultStatus = 200
var standardGinMetrics = []*Metric{
	&Metric{
		ID:          "reqCnt",
		Name:        "requests_total",
		Description: "How many HTTP requests processed, partitioned by status code and HTTP method.",
		Type:        "counter_vec",
		Args:        []string{"code", "method", "host", "url"},
	},
	&Metric{
		ID:          "reqDur",
		Name:        "request_duration_seconds",
		Description: "The HTTP request latencies in seconds.",
		Type:        "summary",
	},
	&Metric{
		ID:          "resSz",
		Name:        "response_size_bytes",
		Description: "The HTTP response sizes in bytes.",
		Type:        "summary",
	},
	&Metric{
		ID:          "reqSz",
		Name:        "request_size_bytes",
		Description: "The HTTP request sizes in bytes.",
		Type:        "summary",
	},
}

/*
RequestCounterURLLabelMappingFn is a function which can be supplied to the middleware to control
the cardinality of the request counter's "url" label, which might be required in some contexts.
For instance, if for a "/customer/:name" route you don't want to generate a time series for every
possible customer name, you could use this function:

This can only use the request and params fields.

func(c *gin.Context) string {
	url := c.Request.URL.String()
	for _, p := range c.Params {
		if p.Key == "name" {
			url = strings.Replace(url, p.Value, ":name", 1)
			break
		}
	}
	return url
}

which would map "/customer/alice" and "/customer/bob" to their template "/customer/:name".
*/
type RequestCounterURLLabelMappingFn func(c *gin.Context) string

// Prometheus contains the metrics gathered by the instance and its path
type PromGin struct {
	*Prometheus
	ReqCntURLLabelMappingFn RequestCounterURLLabelMappingFn
}

// NewPromGin generates a new set of metrics with a certain subsystem name
func NewPromGin(l logger.Logger, subsystem string, rculmf RequestCounterURLLabelMappingFn, customMetricsList ...[]*Metric) *PromGin {

	var metricsList []*Metric

	if len(customMetricsList) > 1 {
		panic("Too many args. NewProGin( string, nil, <optional []*Metric> ).")
	} else if len(customMetricsList) == 1 {
		metricsList = customMetricsList[0]
	}
	for _, m := range standardGinMetrics {
		m2 := *m
		metricsList = append(metricsList, &m2)
	}

	if rculmf == nil {
		rculmf = func(c *gin.Context) string {
			return c.Request.URL.String() // i.e. by default do nothing, i.e. return URL as is
		}
	}

	p := &PromGin{
		Prometheus:              NewPrometheus(l, subsystem, metricsList),
		ReqCntURLLabelMappingFn: rculmf,
	}
	return p
}

func (p *PromGin) HandlerGinFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		reqSz := computeApproximateRequestSize(c.Request)

		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		elapsed := float64(time.Since(start)) / float64(time.Second)
		resSz := float64(c.Writer.Size())

		p.Observe("reqDur", elapsed)
		p.Observe("reqSz", float64(reqSz))
		p.Observe("resSz", resSz)
		url := p.ReqCntURLLabelMappingFn(c)
		p.CounterWithLabelValues("reqCnt", status, c.Request.Method, c.Request.Host, url).Inc()
	}
}

func (p *PromGin) Handler(responder http.Handler) http.Handler {
	return &PromResponder{p: p, responder: responder}
}

type PromResponder struct {
	p         *PromGin
	responder http.Handler
}

type sizeStatusRecorder struct {
	http.ResponseWriter
	status int
	size   int
}

func (rec *sizeStatusRecorder) Written() bool {
	return rec.size != noWritten
}

func (rec *sizeStatusRecorder) WriteHeaderNow() {
	if !rec.Written() {
		rec.size = 0
		rec.status = defaultStatus
		rec.ResponseWriter.WriteHeader(defaultStatus)
	}
}

func (rec *sizeStatusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.size = 0
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *sizeStatusRecorder) Write(b []byte) (n int, err error) {
	rec.WriteHeaderNow()
	n, err = rec.ResponseWriter.Write(b)
	rec.size += n
	return
}

func (rec *sizeStatusRecorder) WriteString(s string) (n int, err error) {
	rec.WriteHeaderNow()
	n, err = io.WriteString(rec.ResponseWriter, s)
	rec.size += n
	return
}

func (pr *PromResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqSz := computeApproximateRequestSize(r)

	w2 := &sizeStatusRecorder{ResponseWriter: w, size: noWritten}
	pr.responder.ServeHTTP(w2, r)

	status := strconv.Itoa(w2.status)
	elapsed := float64(time.Since(start)) / float64(time.Second)
	resSz := float64(w2.size)

	pr.p.Observe("reqDur", elapsed)
	pr.p.Observe("reqSz", float64(reqSz))
	pr.p.Observe("resSz", resSz)
	c := &gin.Context{Request: r, Params: []gin.Param{}}
	url := pr.p.ReqCntURLLabelMappingFn(c)
	hostIndex := strings.LastIndex(r.RemoteAddr, ":")
	pr.p.CounterWithLabelValues("reqCnt", status, r.Method, r.RemoteAddr[:hostIndex], url).Inc()
}

// From https://github.com/DanielHeckrath/gin-prometheus/blob/master/gin_prometheus.go
func computeApproximateRequestSize(r *http.Request) int {
	s := 0
	if r.URL != nil {
		s = len(r.URL.String())
	}

	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return s
}
