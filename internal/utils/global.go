package utils

import (
	"time"

	"google.golang.org/genproto/googleapis/type/date"
	"google.golang.org/genproto/googleapis/type/datetime"
)

func TimeMustParse(layout string) time.Time {
	t, err := time.Parse("2006-01-02", layout)
	if err != nil {
		panic(err)
	}
	return t
}

func ConvertToDateTime(t time.Time) *datetime.DateTime {
	return &datetime.DateTime{
		Year:    int32(t.Year()),
		Month:   int32(t.Month()),
		Day:     int32(t.Day()),
		Hours:   int32(t.Hour()),
		Minutes: int32(t.Minute()),
		Seconds: int32(t.Second()),
		Nanos:   int32(t.Nanosecond()),
	}
}

// Convert a string in "YYYY-MM-DD" format to *date.Date
func ConvertToDate(dateStr string) (*date.Date, error) {
	parsedTime, err := time.Parse("2006-01-02", dateStr) // "YYYY-MM-DD" format
	if err != nil {
		return nil, err
	}
	return &date.Date{
		Year:  int32(parsedTime.Year()),
		Month: int32(parsedTime.Month()),
		Day:   int32(parsedTime.Day()),
	}, nil
}

func CheckAndCovertToDate(dateStr string) (string, error) {
	parsedTime, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return "", err
	}
	return parsedTime.Format("2006-01-02"), nil
}
