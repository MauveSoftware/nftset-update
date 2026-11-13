package prefixlist

import (
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		is6   bool
		want  []string
	}{
		{
			name:  "addresses and prefixes, sorted",
			input: "10.0.1.0/24\n10.0.0.1\n",
			want:  []string{"10.0.0.1", "10.0.1.0-10.0.1.255"},
		},
		{
			name:  "comments, blank lines and whitespace",
			input: "# header\n\n  10.0.0.1  \r\n\t# indented comment\n10.0.0.2/32",
			want:  []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:  "adjacent prefixes stay separate",
			input: "10.0.0.0/31\n10.0.0.2/31\n",
			want:  []string{"10.0.0.0-10.0.0.1", "10.0.0.2-10.0.0.3"},
		},
		{
			name:  "ipv4-mapped address and prefix are normalized",
			input: "::ffff:10.0.0.1\n::ffff:10.0.1.0/120\n",
			want:  []string{"10.0.0.1", "10.0.1.0-10.0.1.255"},
		},
		{
			name:  "last address",
			input: "255.255.255.255\n",
			want:  []string{"255.255.255.255"},
		},
		{
			name:  "ipv6",
			input: "2001:db8::/127\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n",
			is6:   true,
			want:  []string{"2001:db8::-2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		},
		{
			name:  "empty input",
			input: "# nothing\n\n",
			want:  []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tt.input), tt.is6)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotStr := make([]string, 0, len(got))
			for _, iv := range got {
				gotStr = append(gotStr, iv.String())
			}
			if strings.Join(gotStr, ",") != strings.Join(tt.want, ",") {
				t.Errorf("got %v, want %v", gotStr, tt.want)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		is6     bool
		wantErr string
	}{
		{"garbage", "10.0.0.1\nfoo\n", false, "line 2"},
		{"host bits set", "10.0.0.1/24\n", false, "host bits"},
		{"ipv6 in ipv4 set", "2001:db8::1\n", false, "family"},
		{"ipv4 in ipv6 set", "10.0.0.1\n", true, "family"},
		{"overlap", "10.0.0.0/24\n10.0.0.5\n", false, "overlaps"},
		{"duplicate", "10.0.0.5\n10.0.0.5\n", false, "overlaps"},
		{"invalid prefix length", "10.0.0.0/33\n", false, "line 1"},
		{"zone", "fe80::1%eth0\n", true, "line 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.input), tt.is6)
			if err == nil {
				t.Fatalf("expected error containing %q, got none", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}
