package main

import "testing"

func TestFileURLFromPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "unix", path: "/tmp/demo/report.html", want: "file:///tmp/demo/report.html"},
		{name: "windows drive", path: `C:\\Users\\demo\\report.html`, want: "file:///C:/Users/demo/report.html"},
		{name: "unc", path: `\\\\server\\share\\report.html`, want: "file://server/share/report.html"},
		{name: "empty", path: "", want: ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := fileURLFromPath(tc.path)
			if got != tc.want {
				t.Fatalf("fileURLFromPath(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}
