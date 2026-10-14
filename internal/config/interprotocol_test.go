package config

import "testing"

func TestInterprotocolSamplingUsesMassLayout(t *testing.T) {
	for _, count := range []int{2, 3} {
		c := &IPIDConfig{ConnectionCount: 4, RequestsPerConnection: 4, RequestIPIDs: []uint16{18933, 18932, 3717, 3718, 3719}}
		if err := ConfigureInterprotocolSampling(c, count); err != nil {
			t.Fatal(err)
		}
		if c.ConnectionCount != 4 || c.RequestsPerConnection != 25 {
			t.Fatalf("got %dx%d sampling", c.ConnectionCount, c.RequestsPerConnection)
		}
	}
}

func TestInterprotocolSamplingRejectsAliasedReflectionPatterns(t *testing.T) {
	for _, test := range []struct {
		count   int
		pattern []uint16
	}{
		{2, nil}, {2, []uint16{1}}, {2, []uint16{1, 2}},
		{3, []uint16{1, 2, 3}}, {1, []uint16{1, 2, 3, 4, 5}},
	} {
		c := &IPIDConfig{RequestIPIDs: test.pattern}
		if err := ConfigureInterprotocolSampling(c, test.count); err == nil {
			t.Fatalf("accepted ambiguous pattern %v with %d protocols", test.pattern, test.count)
		}
	}
}
