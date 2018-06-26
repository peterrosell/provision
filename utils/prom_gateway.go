package utils

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/digitalrebar/logger"
)

// PrometheusPushGateway contains the configuration for pushing to a Prometheus pushgateway (optional)
type PrometheusPushGateway struct {
	// Push interval in seconds
	pushIntervalSeconds time.Duration

	// Push Gateway URL in format http://domain:port
	// where JOBNAME can be any string of your choice
	pushGatewayURL string

	// Local metrics URL where metrics are fetched from, this could be ommited in the future
	// if implemented using prometheus common/expfmt instead
	metricsURL string

	// pushgateway job name, defaults to "gin"
	job string

	// Logger for output
	l logger.Logger
}

// SetPushGateway sends metrics to a remote pushgateway exposed on pushGatewayURL
// every pushIntervalSeconds. Metrics are fetched from metricsURL
func NewPrometheusPushGateway(l logger.Logger, pushGatewayURL, metricsURL string, pushIntervalSeconds time.Duration) *PrometheusPushGateway {
	ppg := &PrometheusPushGateway{
		pushGatewayURL:      pushGatewayURL,
		metricsURL:          metricsURL,
		pushIntervalSeconds: pushIntervalSeconds,
		job:                 "gin",
		l:                   l,
	}
	ppg.startPushTicker()
	return ppg
}

func (ppg *PrometheusPushGateway) getMetrics() []byte {
	response, _ := http.Get(ppg.metricsURL)

	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)

	return body
}

func (ppg *PrometheusPushGateway) getPushGatewayURL() string {
	h, _ := os.Hostname()
	return ppg.pushGatewayURL + "/metrics/job/" + ppg.job + "/instance/" + h
}

func (ppg *PrometheusPushGateway) sendMetricsToPushGateway(metrics []byte) {
	req, err := http.NewRequest("POST", ppg.getPushGatewayURL(), bytes.NewBuffer(metrics))
	client := &http.Client{}
	_, err = client.Do(req)
	if err != nil {
		ppg.l.Errorf("Error sending to push gatway: " + err.Error())
	}
}

func (ppg *PrometheusPushGateway) startPushTicker() {
	ticker := time.NewTicker(time.Second * ppg.pushIntervalSeconds)
	go func() {
		for range ticker.C {
			ppg.sendMetricsToPushGateway(ppg.getMetrics())
		}
	}()
}
