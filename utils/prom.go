package utils

import (
	"github.com/digitalrebar/logger"
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus contains the metrics gathered by the instance and its path
type Prometheus struct {
	metrics map[string]*Metric
	l       logger.Logger
}

// NewPrometheus generates a new set of metrics with a certain subsystem name
func NewPrometheus(l logger.Logger, subsystem string, metricsList []*Metric) *Prometheus {
	metrics := map[string]*Metric{}
	for _, m := range metricsList {
		NewMetric(l, m, subsystem)
		metrics[m.ID] = m
	}

	p := &Prometheus{
		metrics: metrics,
		l:       l,
	}

	return p
}

func (p *Prometheus) Observe(id string, d float64) {
	m, ok := p.metrics[id]
	if !ok {
		p.l.Errorf("Failed to lookup metric: %s", id)
		return
	}
	o, ok := m.MetricCollector.(prometheus.Observer)
	if !ok {
		p.l.Errorf("metric, %s, is not an Observer", id)
		return
	}
	o.Observe(d)
}

func (p *Prometheus) CounterWithLabelValues(id string, args ...string) prometheus.Counter {
	m, ok := p.metrics[id]
	if !ok {
		p.l.Errorf("Failed to lookup metric with labels: %s", id)
		return nil
	}
	o, ok := m.MetricCollector.(*prometheus.CounterVec)
	if !ok {
		p.l.Errorf("metric, %s, is not an CounterVec, %+v", id, m.MetricCollector)
		return nil
	}
	return o.WithLabelValues(args...)
}
