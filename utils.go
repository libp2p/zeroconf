package zeroconf

import (
	"strings"
	"time"
)

func parseSubtypes(service string) (string, []string) {
	subtypes := strings.Split(service, ",")
	return subtypes[0], subtypes[1:]
}

// trimDot is used to trim the dots from the start or end of a string
func trimDot(s string) string {
	return strings.Trim(s, ".")
}

type DeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

func setDeadline(timeout time.Duration, ds DeadlineSetter) {
	if timeout != 0 {
		ds.SetWriteDeadline(time.Now().Add(timeout))
	} else {
		ds.SetWriteDeadline(time.Time{})
	}
}
