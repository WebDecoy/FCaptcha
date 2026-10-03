package main

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

const cadenceReason = "Keystroke cadence analysis"

// approx compares floats that went through different arithmetic orders in
// three languages; bit-equality would make the shared fixtures flaky.
func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// TestCadenceSharedFixtures runs the cadence vectors through the public form
// analysis path, the same way server-node and server-python consume them.
func TestCadenceSharedFixtures(t *testing.T) {
	data, err := os.ReadFile("../test/fixtures/keystroke-cadence.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Name     string
			Stats    map[string]interface{}
			Expected *struct {
				Score             float64
				Confidence        float64
				CadenceHumanScore float64
				Metrics           map[string]float64
			}
		}
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	e := NewScoringEngine("test-secret")

	for _, f := range fixtures.Cases {
		t.Run(f.Name, func(t *testing.T) {
			form := map[string]interface{}{
				"textareaKeyboard": map[string]interface{}{"message": f.Stats},
			}
			var got *DetectionResult
			for _, d := range e.AnalyzeFormInteraction(form, true) {
				if strings.HasPrefix(d.Reason, cadenceReason) {
					d := d
					got = &d
				}
			}

			if f.Expected == nil {
				if got != nil {
					t.Fatalf("cadence fired: %+v", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("cadence did not fire")
			}
			want := f.Expected
			if got.Category != CategoryBot || !approx(got.Score, want.Score) || !approx(got.Confidence, want.Confidence) {
				t.Errorf("got %s score %v confidence %v, want bot score %v confidence %v",
					got.Category, got.Score, got.Confidence, want.Score, want.Confidence)
			}
			if h, _ := got.Details["cadenceHumanScore"].(float64); !approx(h, want.CadenceHumanScore) {
				t.Errorf("cadenceHumanScore = %v, want %v", h, want.CadenceHumanScore)
			}
			metrics, _ := got.Details["metrics"].(map[string]interface{})
			if len(metrics) != len(want.Metrics) {
				t.Errorf("metrics = %v, want %v", metrics, want.Metrics)
			}
			for k, w := range want.Metrics {
				if m, ok := metrics[k].(float64); !ok || !approx(m, w) {
					t.Errorf("metric %s = %v, want %v", k, metrics[k], w)
				}
			}
		})
	}
}

func TestCadenceIgnoresMissingAndMalformedStats(t *testing.T) {
	for name, stats := range map[string]map[string]interface{}{
		"nil":               nil,
		"empty":             {},
		"intervals not arr": {"keyCount": 40.0, "intervals": "100,100"},
	} {
		if got := analyzeKeystrokeCadence(stats); got != nil {
			t.Errorf("%s: got %+v, want nil", name, *got)
		}
	}
}

func TestCadenceConfidenceCappedAtPointSeven(t *testing.T) {
	// All seven metrics active would give 7/7; the detector deliberately stays
	// contributory.
	got := analyzeKeystrokeCadence(map[string]interface{}{
		"keyCount":   41.0,
		"intervals":  floatsAny(repeat(100, 9, 500, 4)),
		"dwellTimes": floatsAny(repeat(50, 40, 0, 0)),
		"rollovers":  0.0,
	})
	if got == nil {
		t.Fatal("cadence did not fire")
	}
	if got.Confidence != 0.7 {
		t.Errorf("confidence = %v, want 0.7", got.Confidence)
	}
	if n := len(got.Details["metrics"].(map[string]interface{})); n != 7 {
		t.Errorf("%d metrics active, want all 7", n)
	}
}

// repeat builds n runs of (base x k, then one pause), or k copies of base when
// n is zero.
func repeat(base float64, k int, pause float64, n int) []float64 {
	var out []float64
	if n == 0 {
		for i := 0; i < k; i++ {
			out = append(out, base)
		}
		return out
	}
	for j := 0; j < n; j++ {
		for i := 0; i < k; i++ {
			out = append(out, base)
		}
		out = append(out, pause)
	}
	return out
}

func floatsAny(fs []float64) []interface{} {
	out := make([]interface{}, len(fs))
	for i, f := range fs {
		out[i] = f
	}
	return out
}

func TestStatMeanAndStddev(t *testing.T) {
	if statMean(nil) != 0 || statStddev([]float64{5}) != 0 {
		t.Error("empty and single-sample inputs must be 0")
	}
	xs := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	if got := statMean(xs); got != 5 {
		t.Errorf("mean = %v, want 5", got)
	}
	// Population, not sample, standard deviation: the classic example is 2.
	if got := statStddev(xs); got != 2 {
		t.Errorf("stddev = %v, want 2", got)
	}
}

func TestStatErfMatchesStdlib(t *testing.T) {
	// Abramowitz & Stegun 7.1.26, whose stated maximum error is 1.5e-7.
	for x := -4.0; x <= 4.0; x += 0.125 {
		if d := math.Abs(statErf(x) - math.Erf(x)); d > 1.5e-7 {
			t.Errorf("erf(%v) off by %v", x, d)
		}
	}
}

func TestStatNormalCDF(t *testing.T) {
	cases := []struct{ x, mu, sigma, want float64 }{
		{0, 0, 1, 0.5},
		{1.959963985, 0, 1, 0.975},
		{-1, 0, 1, 0.158655254},
		{12, 10, 2, 0.841344746},
		// Degenerate distribution: a step at mu.
		{5, 5, 0, 1},
		{4.9, 5, 0, 0},
	}
	for _, c := range cases {
		if got := statNormalCDF(c.x, c.mu, c.sigma); math.Abs(got-c.want) > 2e-7 {
			t.Errorf("Φ(%v; %v, %v) = %v, want %v", c.x, c.mu, c.sigma, got, c.want)
		}
	}
}

func TestStatKSTestStatistic(t *testing.T) {
	uniform := func(x float64) float64 { return math.Max(0, math.Min(1, x)) }
	if got := statKSTestStatistic(nil, uniform); got != 0 {
		t.Errorf("empty sample: D = %v", got)
	}
	// Evenly spaced midpoints: the empirical CDF sits exactly 1/(2n) off at
	// every step, which is the smallest D any n-point sample can reach.
	if got := statKSTestStatistic([]float64{0.125, 0.375, 0.625, 0.875}, uniform); !approx(got, 0.125) {
		t.Errorf("midpoints: D = %v, want 0.125", got)
	}
	// All mass at one end: D approaches 1.
	if got := statKSTestStatistic([]float64{0.99, 0.99, 0.99, 0.99}, uniform); !approx(got, 0.99) {
		t.Errorf("clumped: D = %v, want 0.99", got)
	}
	// Input order must not matter, and the input must not be reordered.
	in := []float64{0.875, 0.125, 0.625, 0.375}
	if got := statKSTestStatistic(in, uniform); !approx(got, 0.125) {
		t.Errorf("unsorted: D = %v, want 0.125", got)
	}
	if in[0] != 0.875 {
		t.Error("statKSTestStatistic sorted its input in place")
	}
}

func TestStatShannonEntropy(t *testing.T) {
	if statShannonEntropy(nil, 10) != 0 || statShannonEntropy([]float64{3, 3, 3}, 10) != 0 {
		t.Error("empty and constant inputs carry no entropy")
	}
	// One value per bin: log2(bins). The maximum lands in the last bin rather
	// than overflowing it.
	var spread []float64
	for i := 0; i <= 8; i++ {
		spread = append(spread, float64(i))
	}
	if got := statShannonEntropy(spread[:8], 8); !approx(got, 3) {
		t.Errorf("one value per bin: H = %v, want 3", got)
	}
	// Two equal halves: exactly one bit.
	if got := statShannonEntropy([]float64{0, 0, 0, 1, 1, 1}, 10); !approx(got, 1) {
		t.Errorf("two halves: H = %v, want 1", got)
	}
}

func TestStatLag1Autocorrelation(t *testing.T) {
	if statLag1Autocorrelation([]float64{1, 2}) != 0 {
		t.Error("fewer than 3 samples must be 0")
	}
	if statLag1Autocorrelation([]float64{4, 4, 4, 4}) != 0 {
		t.Error("constant series must be 0, not NaN")
	}
	if got := statLag1Autocorrelation([]float64{1, 2, 3, 4, 5, 6}); !approx(got, 1) {
		t.Errorf("trend: r = %v, want 1", got)
	}
	if got := statLag1Autocorrelation([]float64{1, -1, 1, -1, 1, -1}); !approx(got, -1) {
		t.Errorf("alternating: r = %v, want -1", got)
	}
}

func TestGetFloatSlice(t *testing.T) {
	if getFloatSlice(nil, "k") != nil {
		t.Error("nil map must give nil")
	}
	if getFloatSlice(map[string]interface{}{"k": []float64{1}}, "k") != nil {
		t.Error("only JSON-decoded []interface{} is accepted")
	}
	got := getFloatSlice(map[string]interface{}{"k": []interface{}{1.5, 2, "x", nil, 3.0}}, "k")
	if len(got) != 3 || got[0] != 1.5 || got[1] != 2 || got[2] != 3 {
		t.Errorf("mixed values = %v, want [1.5 2 3]", got)
	}
}
