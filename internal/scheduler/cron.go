package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseCronExpression parses a cron expression and returns a CronExpression.
// Supports standard 5-field cron syntax: minute hour day-of-month month day-of-week
// Examples:
//   - "0 2 * * *" = Every day at 2:00 AM
//   - "*/15 * * * *" = Every 15 minutes
//   - "0 */2 * * *" = Every 2 hours
//   - "0 0 1 * *" = First day of every month at midnight
func ParseCronExpression(expr string) (*CronExpression, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("invalid cron expression: expected 5 fields (minute hour day-of-month month day-of-week), got %d", len(fields))
	}

	cron := &CronExpression{
		Minute:     fields[0],
		Hour:       fields[1],
		DayOfMonth: fields[2],
		Month:      fields[3],
		DayOfWeek:  fields[4],
	}

	// Validate each field
	if err := validateCronField(cron.Minute, 0, 59, "minute"); err != nil {
		return nil, err
	}
	if err := validateCronField(cron.Hour, 0, 23, "hour"); err != nil {
		return nil, err
	}
	if err := validateCronField(cron.DayOfMonth, 1, 31, "day-of-month"); err != nil {
		return nil, err
	}
	if err := validateCronField(cron.Month, 1, 12, "month"); err != nil {
		return nil, err
	}
	if err := validateCronField(cron.DayOfWeek, 0, 7, "day-of-week"); err != nil {
		return nil, err
	}

	return cron, nil
}

// validateCronField validates a single cron field.
func validateCronField(field string, min, max int, name string) error {
	// Allow wildcard
	if field == "*" {
		return nil
	}

	// Handle step values (*/n)
	if strings.HasPrefix(field, "*/") {
		stepStr := strings.TrimPrefix(field, "*/")
		step, err := strconv.Atoi(stepStr)
		if err != nil {
			return fmt.Errorf("invalid %s step value: %s", name, stepStr)
		}
		if step < 1 {
			return fmt.Errorf("%s step must be >= 1", name)
		}
		return nil
	}

	// Handle ranges (n-m)
	if strings.Contains(field, "-") {
		parts := strings.Split(field, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid %s range: %s", name, field)
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("invalid %s range start: %s", name, parts[0])
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid %s range end: %s", name, parts[1])
		}
		if start < min || start > max {
			return fmt.Errorf("%s range start %d out of range [%d-%d]", name, start, min, max)
		}
		if end < min || end > max {
			return fmt.Errorf("%s range end %d out of range [%d-%d]", name, end, min, max)
		}
		if start > end {
			return fmt.Errorf("%s range start must be <= end", name)
		}
		return nil
	}

	// Handle lists (n,m,o)
	if strings.Contains(field, ",") {
		parts := strings.Split(field, ",")
		for _, part := range parts {
			if err := validateCronField(part, min, max, name); err != nil {
				return err
			}
		}
		return nil
	}

	// Handle single values
	val, err := strconv.Atoi(field)
	if err != nil {
		return fmt.Errorf("invalid %s value: %s", name, field)
	}
	if val < min || val > max {
		return fmt.Errorf("%s value %d out of range [%d-%d]", name, val, min, max)
	}

	return nil
}

// CalculateNextRun calculates the next run time for a cron expression after the given time.
func CalculateNextRun(cron *CronExpression, after time.Time) (time.Time, error) {
	// Start from the next minute
	next := after.Truncate(time.Minute).Add(time.Minute)

	// Try up to 4 years in the future (reasonable limit)
	maxAttempts := 525600 * 4 // 4 years worth of minutes
	for i := 0; i < maxAttempts; i++ {
		if matchesCronExpression(cron, next) {
			return next, nil
		}
		next = next.Add(time.Minute)
	}

	return time.Time{}, fmt.Errorf("no matching time found within 4 years")
}

// matchesCronExpression checks if a time matches a cron expression.
func matchesCronExpression(cron *CronExpression, t time.Time) bool {
	return matchesField(cron.Minute, t.Minute(), 0, 59) &&
		matchesField(cron.Hour, t.Hour(), 0, 23) &&
		matchesField(cron.DayOfMonth, t.Day(), 1, 31) &&
		matchesField(cron.Month, int(t.Month()), 1, 12) &&
		matchesField(cron.DayOfWeek, int(t.Weekday()), 0, 7)
}

// matchesField checks if a value matches a cron field.
func matchesField(field string, value, min, max int) bool {
	// Wildcard matches everything
	if field == "*" {
		return true
	}

	// Handle step values (*/n)
	if strings.HasPrefix(field, "*/") {
		stepStr := strings.TrimPrefix(field, "*/")
		step, err := strconv.Atoi(stepStr)
		if err != nil {
			return false
		}
		return value%step == 0
	}

	// Handle ranges (n-m)
	if strings.Contains(field, "-") {
		parts := strings.Split(field, "-")
		if len(parts) != 2 {
			return false
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return false
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return false
		}
		return value >= start && value <= end
	}

	// Handle lists (n,m,o)
	if strings.Contains(field, ",") {
		parts := strings.Split(field, ",")
		for _, part := range parts {
			if matchesField(part, value, min, max) {
				return true
			}
		}
		return false
	}

	// Handle single values
	val, err := strconv.Atoi(field)
	if err != nil {
		return false
	}

	// Special case for day of week: 0 and 7 both mean Sunday
	if min == 0 && max == 7 && (val == 0 || val == 7) && (value == 0 || value == 7) {
		return true
	}

	return val == value
}

// String returns a human-readable description of the cron expression.
func (c *CronExpression) String() string {
	return fmt.Sprintf("%s %s %s %s %s", c.Minute, c.Hour, c.DayOfMonth, c.Month, c.DayOfWeek)
}

// DescribeCronExpression returns a human-readable description of what the cron expression means.
func DescribeCronExpression(cron *CronExpression) string {
	// Simple descriptions for common patterns
	if cron.Minute == "0" && cron.Hour == "*" && cron.DayOfMonth == "*" && cron.Month == "*" && cron.DayOfWeek == "*" {
		return "Every hour"
	}
	if cron.Minute == "*/15" && cron.Hour == "*" && cron.DayOfMonth == "*" && cron.Month == "*" && cron.DayOfWeek == "*" {
		return "Every 15 minutes"
	}
	if cron.Minute == "0" && cron.Hour == "0" && cron.DayOfMonth == "*" && cron.Month == "*" && cron.DayOfWeek == "*" {
		return "Daily at midnight"
	}
	if cron.Minute == "0" && cron.Hour == "0" && cron.DayOfMonth == "1" && cron.Month == "*" && cron.DayOfWeek == "*" {
		return "Monthly on the 1st at midnight"
	}
	if cron.Minute == "0" && cron.Hour == "0" && cron.DayOfMonth == "*" && cron.Month == "*" && cron.DayOfWeek == "0" {
		return "Weekly on Sunday at midnight"
	}

	// Generic description
	return fmt.Sprintf("At %s:%s on day %s of month %s on weekday %s",
		describeCronField(cron.Hour, "hour"),
		describeCronField(cron.Minute, "minute"),
		describeCronField(cron.DayOfMonth, "day"),
		describeCronField(cron.Month, "month"),
		describeCronField(cron.DayOfWeek, "weekday"))
}

func describeCronField(field, name string) string {
	if field == "*" {
		return "every " + name
	}
	if strings.HasPrefix(field, "*/") {
		return "every " + strings.TrimPrefix(field, "*/") + " " + name + "s"
	}
	return field
}
