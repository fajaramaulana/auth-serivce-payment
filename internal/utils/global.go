package utils

import "time"

func TimeMustParse(layout string) time.Time {
	t, err := time.Parse("2006-01-02", layout)
	if err != nil {
		panic(err)
	}
	return t
}
