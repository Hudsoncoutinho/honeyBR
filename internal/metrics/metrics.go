package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	EventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "honeybr_events_total",
			Help: "Total events captured by HoneyBR",
		},
		[]string{"type"},
	)
)

func Register() {
	prometheus.MustRegister(EventsTotal)
}
