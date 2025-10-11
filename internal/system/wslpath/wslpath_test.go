package wslpath

import "testing"

func TestToWindows(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"/mnt/c/Users/alice", "C:\\Users\\alice", false},
		{"/mnt/d/projects", "D:\\projects", false},
		{"/mnt/z", "Z:", false},
		{"/home/alice", "", true},
		{"", "", true},
		{"/mnt/1/data", "", true},
	}

	for _, tc := range tests {
		got, err := ToWindows(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ToWindows(%q) expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ToWindows(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.expected {
			t.Fatalf("ToWindows(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestToWSL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"C:/Users/alice", "/mnt/c/Users/alice", false},
		{"D:\\projects", "/mnt/d/projects", false},
		{"Z:", "/mnt/z", false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tc := range tests {
		got, err := ToWSL(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ToWSL(%q) expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ToWSL(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.expected {
			t.Fatalf("ToWSL(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
