package perf

import "testing"

func TestCPUDeltaRegression(t *testing.T) {
	t.Parallel()
	base := BusWorkloadMetrics{CPUSeconds: 1.0}
	curr := BusWorkloadMetrics{CPUSeconds: 1.25}
	delta := cpuDelta("fanout", base.CPUSeconds, curr.CPUSeconds, 0.10)
	if !delta.Regression {
		t.Fatalf("expected regression when CPU increases by >10%%: %+v", delta)
	}
	if delta.ChangePercent <= 0 {
		t.Fatalf("expected positive change percent, got %.2f", delta.ChangePercent)
	}
}

func TestCPUDeltaImprovement(t *testing.T) {
	t.Parallel()
	base := BusWorkloadMetrics{CPUSeconds: 2.0}
	curr := BusWorkloadMetrics{CPUSeconds: 1.5}
	delta := cpuDelta("fanout", base.CPUSeconds, curr.CPUSeconds, 0.10)
	if delta.Regression {
		t.Fatalf("did not expect regression when CPU decreased: %+v", delta)
	}
	if delta.ChangePercent >= 0 {
		t.Fatalf("expected negative change percent for improvement: %.2f", delta.ChangePercent)
	}
}
