package scheduler

import (
	"testing"
	"time"
)

func TestParseCronExpression(t *testing.T) {
	tests := []struct {
		name      string
		expr      string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid daily at 2am",
			expr:    "0 2 * * *",
			wantErr: false,
		},
		{
			name:    "valid every 15 minutes",
			expr:    "*/15 * * * *",
			wantErr: false,
		},
		{
			name:    "valid hourly",
			expr:    "0 * * * *",
			wantErr: false,
		},
		{
			name:    "valid weekly",
			expr:    "0 0 * * 0",
			wantErr: false,
		},
		{
			name:    "valid monthly",
			expr:    "0 0 1 * *",
			wantErr: false,
		},
		{
			name:    "valid range",
			expr:    "0 9-17 * * *",
			wantErr: false,
		},
		{
			name:    "valid list",
			expr:    "0 0 * * 1,3,5",
			wantErr: false,
		},
		{
			name:      "invalid field count",
			expr:      "0 2 * *",
			wantErr:   true,
			errSubstr: "expected 5 fields",
		},
		{
			name:      "invalid minute",
			expr:      "60 2 * * *",
			wantErr:   true,
			errSubstr: "minute value",
		},
		{
			name:      "invalid hour",
			expr:      "0 24 * * *",
			wantErr:   true,
			errSubstr: "hour value",
		},
		{
			name:      "invalid day of month",
			expr:      "0 0 32 * *",
			wantErr:   true,
			errSubstr: "day-of-month value",
		},
		{
			name:      "invalid month",
			expr:      "0 0 1 13 *",
			wantErr:   true,
			errSubstr: "month value",
		},
		{
			name:      "invalid day of week",
			expr:      "0 0 * * 8",
			wantErr:   true,
			errSubstr: "day-of-week value",
		},
		{
			name:      "invalid step",
			expr:      "*/invalid * * * *",
			wantErr:   true,
			errSubstr: "invalid minute step value",
		},
		{
			name:      "invalid range",
			expr:      "0 17-9 * * *",
			wantErr:   true,
			errSubstr: "range start must be <= end",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cron, err := ParseCronExpression(tt.expr)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCronExpression() expected error but got none")
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("ParseCronExpression() error = %v, want substring %q", err, tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseCronExpression() error = %v, want nil", err)
				return
			}
			if cron == nil {
				t.Errorf("ParseCronExpression() returned nil cron")
			}
		})
	}
}

func TestCalculateNextRun(t *testing.T) {
	tests := []struct {
		name        string
		cronExpr    string
		after       time.Time
		expectHour  int
		expectMin   int
		expectWDay  *time.Weekday
	}{
		{
			name:       "daily at 2am",
			cronExpr:   "0 2 * * *",
			after:      time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			expectHour: 2,
			expectMin:  0,
		},
		{
			name:       "every hour",
			cronExpr:   "0 * * * *",
			after:      time.Date(2025, 1, 15, 14, 30, 0, 0, time.UTC),
			expectHour: 15,
			expectMin:  0,
		},
		{
			name:       "every 15 minutes",
			cronExpr:   "*/15 * * * *",
			after:      time.Date(2025, 1, 15, 14, 7, 0, 0, time.UTC),
			expectMin:  15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cron, err := ParseCronExpression(tt.cronExpr)
			if err != nil {
				t.Fatalf("ParseCronExpression() error = %v", err)
			}

			next, err := CalculateNextRun(cron, tt.after)
			if err != nil {
				t.Fatalf("CalculateNextRun() error = %v", err)
			}

			if !next.After(tt.after) {
				t.Errorf("CalculateNextRun() = %v, expected after %v", next, tt.after)
			}

			if tt.expectHour > 0 && next.Hour() != tt.expectHour {
				t.Errorf("CalculateNextRun() hour = %d, want %d", next.Hour(), tt.expectHour)
			}

			if tt.expectMin >= 0 && next.Minute() != tt.expectMin {
				t.Errorf("CalculateNextRun() minute = %d, want %d", next.Minute(), tt.expectMin)
			}

			if tt.expectWDay != nil && next.Weekday() != *tt.expectWDay {
				t.Errorf("CalculateNextRun() weekday = %v, want %v", next.Weekday(), *tt.expectWDay)
			}
		})
	}
}

func TestMatchesCronExpression(t *testing.T) {
	tests := []struct {
		name     string
		cronExpr string
		testTime time.Time
		expected bool
	}{
		{
			name:     "daily at 2am - matches",
			cronExpr: "0 2 * * *",
			testTime: time.Date(2025, 1, 15, 2, 0, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "daily at 2am - doesn't match hour",
			cronExpr: "0 2 * * *",
			testTime: time.Date(2025, 1, 15, 3, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name:     "every 15 minutes - matches",
			cronExpr: "*/15 * * * *",
			testTime: time.Date(2025, 1, 15, 14, 30, 0, 0, time.UTC),
			expected: true,
		},
		{
			name:     "every 15 minutes - doesn't match",
			cronExpr: "*/15 * * * *",
			testTime: time.Date(2025, 1, 15, 14, 17, 0, 0, time.UTC),
			expected: false,
		},
		{
			name:     "weekday range - matches",
			cronExpr: "0 9 * * 1-5",
			testTime: time.Date(2025, 1, 15, 9, 0, 0, 0, time.UTC), // Thursday
			expected: true,
		},
		{
			name:     "weekday range - doesn't match weekend",
			cronExpr: "0 9 * * 1-5",
			testTime: time.Date(2025, 1, 18, 9, 0, 0, 0, time.UTC), // Sunday
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cron, err := ParseCronExpression(tt.cronExpr)
			if err != nil {
				t.Fatalf("ParseCronExpression() error = %v", err)
			}

			result := matchesCronExpression(cron, tt.testTime)
			if result != tt.expected {
				t.Errorf("matchesCronExpression() = %v, want %v for time %v",
					result, tt.expected, tt.testTime)
			}
		})
	}
}

func TestDescribeCronExpression(t *testing.T) {
	tests := []struct {
		name     string
		cronExpr string
		expected string
	}{
		{
			name:     "every hour",
			cronExpr: "0 * * * *",
			expected: "Every hour",
		},
		{
			name:     "every 15 minutes",
			cronExpr: "*/15 * * * *",
			expected: "Every 15 minutes",
		},
		{
			name:     "daily at midnight",
			cronExpr: "0 0 * * *",
			expected: "Daily at midnight",
		},
		{
			name:     "monthly",
			cronExpr: "0 0 1 * *",
			expected: "Monthly on the 1st at midnight",
		},
		{
			name:     "weekly on Sunday",
			cronExpr: "0 0 * * 0",
			expected: "Weekly on Sunday at midnight",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cron, err := ParseCronExpression(tt.cronExpr)
			if err != nil {
				t.Fatalf("ParseCronExpression() error = %v", err)
			}

			result := DescribeCronExpression(cron)
			if result != tt.expected {
				t.Errorf("DescribeCronExpression() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
