package openssh

import "time"

func parseSyslogTimestamp(raw string, year int, loc *time.Location) (*time.Time, error) {
	t, err := time.ParseInLocation("Jan _2 15:04:05 2006", raw+" "+itoa(year), loc)
	if err != nil {
		return nil, err
	}

	return &t, nil
}

func itoa(n int) string {
	return time.Date(n, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006")
}
