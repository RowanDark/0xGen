package perf

// DefaultBusWorkloads enumerates the synthetic scenarios exercised by the
// perfbench command. They are designed to stress different shapes of the
// findings bus: wide fan-out, deep pipelines, and high concurrency emitters.
var DefaultBusWorkloads = []BusWorkloadConfig{
	{
		Name:         "fanout_wide",
		FanOut:       16,
		Depth:        1,
		Concurrency:  4,
		Events:       6000,
		PayloadBytes: 256,
		FailureRate:  0,
		Seed:         42,
	},
	{
		Name:         "fanout_deep",
		FanOut:       6,
		Depth:        3,
		Concurrency:  8,
		Events:       8000,
		PayloadBytes: 384,
		FailureRate:  0,
		Seed:         84,
	},
	{
		Name:         "high_concurrency",
		FanOut:       8,
		Depth:        2,
		Concurrency:  16,
		Events:       10000,
		PayloadBytes: 192,
		FailureRate:  0,
		Seed:         126,
	},
}
