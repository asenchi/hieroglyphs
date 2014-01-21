package hieroglyphs

import (
	"errors"
	"regexp"
	"strconv"
)

var SeverityMap = map[int]string{
	0: "EMERG",
	1: "ALERT",
	2: "CRIT",
	3: "ERR",
	4: "WARNING",
	5: "NOTICE",
	6: "INFO",
	7: "DEBUG",
}

var FacilityMap = map[int]string{
	0:   "KERN",
	8:   "USER",
	16:  "MAIL",
	24:  "DAEMON",
	32:  "AUTH",
	40:  "SYSLOG",
	48:  "LPR",
	56:  "NEWS",
	64:  "UUCP",
	72:  "CRON",
	80:  "AUTHPRIV",
	88:  "FTP",
	128: "LOCAL0",
	136: "LOCAL1",
	144: "LOCAL2",
	152: "LOCAL3",
	160: "LOCAL4",
	168: "LOCAL5",
	176: "LOCAL6",
	184: "LOCAL7",
}

// LogEvents should align with RFC5424
//
// LogEvent structure:
// <86>1 2014-01-20T13:26:55-08:00 hostname-here sshd 16719 - - Received disconnect from 127.0.0.1: 11: disconnected by user
var regexEvent = regexp.MustCompile(
	`^<(\d+)>(\d+) ([^ ]+) ([^ ]+) ([^ ]+) ([^ ]+) - - (.*)$`)

type LogEvent struct {
	Priority  int
	Version   int
	Severity  int
	Facility  int
	Timestamp string // Eventually do datetime here.
	Hostname  string
	Program   string
	Pid       string // Eventually do int here (need to handle the '-' case
	Message   string
	Original  []byte
}

func ParseEvent(buf []byte) (*LogEvent, error) {
	var err error

	match := regexEvent.FindSubmatch(buf)
	if len(match) == 0 {
		return nil, errors.New("No match")
	}

	var prival int
	if len(match[1]) != 0 {
		prival, err = strconv.Atoi(string(match[1]))
		if err != nil {
			return nil, errors.New("Failed to convert prival to integer.")
		}
	}

	var version int
	if len(match[2]) != 0 {
		version, err = strconv.Atoi(string(match[2]))
		if err != nil {
			return nil, errors.New("Failed to convert version to integer.")
		}
	}

	var timestamp string
	if len(match[3]) != 0 {
		timestamp = string(match[3])
	}

	var hostname string
	if len(match[4]) != 0 {
		hostname = string(match[4])
	}

	var progname string
	if len(match[5]) != 0 {
		progname = string(match[5])
	}

	var pid string
	if len(match[6]) != 0 {
		pid = string(match[6])
	}

	var event string
	if len(match[7]) != 0 {
		event = string(match[7])
	}

	evt := &LogEvent{
		Priority:  prival,
		Version:   version,
		Severity:  prival % 8,
		Facility:  prival - (prival % 8),
		Timestamp: timestamp,
		Hostname:  hostname,
		Program:   progname,
		Pid:       pid,
		Message:   event,
		Original:  match[0],
	}

	return evt, nil
}
