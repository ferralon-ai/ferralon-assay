// Package main is a vendored corpus repro for advisory GO-2022-0322 (uncontrolled
// memory consumption in github.com/prometheus/client_golang's promhttp handler when
// parsing malformed scrape requests; vulnerable at v1.11.0). The vulnerable VERSION is
// present in the dependency tree, but this program ONLY registers a metric — it never
// constructs or serves any promhttp.Handler. govulncheck will report the advisory as
// present in the module graph but find NO symbol-level call path to the vulnerable
// promhttp sink, so reachability yields zero ReachPath and no candidate pair is built.
package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	requests := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tegron_repro_requests_total",
		Help: "Total requests (registration only; no promhttp handler is ever served).",
	})
	prometheus.MustRegister(requests)
	requests.Inc()
}
