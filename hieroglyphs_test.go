package hieroglyphs

import (
	"testing"
	"time"
)

var loc, _ = time.LoadLocation("America/Los_Angeles")
var testEvents = []struct {
	RawMessage string
	Event      *LogEvent
}{
	{"<86>1 2014-01-20T13:26:16-08:00 rappel-fe1-pe1-prd sudo - - - pam_unix(sudo:session): session closed for user root", &LogEvent{Priority: 86, Version: 1, Severity: 6, Facility: 80, Timestamp: time.Date(2014, 01, 20, 13, 26, 16, 0, loc), Hostname: "rappel-fe1-pe1-prd", Program: "sudo", Pid: "-", Message: "pam_unix(sudo:session): session closed for user root", Original: []byte("<86>1 2014-01-20T13:26:16-08:00 rappel-fe1-pe1-prd sudo - - - pam_unix(sudo:session): session closed for user root")}},
	{"<86>1 2014-01-20T13:26:16-08:00 rappel-fe1-pe1-prd sshd 16385 - - Received disconnect from 127.0.0.1: 11: disconnected by user", &LogEvent{Priority: 86, Version: 1, Severity: 6, Facility: 80, Timestamp: time.Date(2014, 01, 20, 13, 26, 16, 0, loc), Hostname: "rappel-fe1-pe1-prd", Program: "sshd", Pid: "16385", Message: "Received disconnect from 127.0.0.1: 11: disconnected by user", Original: []byte("<86>1 2014-01-20T13:26:16-08:00 rappel-fe1-pe1-prd sshd 16385 - - Received disconnect from 127.0.0.1: 11: disconnected by user")}},
}

func TestEventParsing(t *testing.T) {
	for _, tt := range testEvents {
		evt, err := ParseEvent([]byte(tt.RawMessage))
		if err != nil {
			t.Fatal(err)
		}

		if evt.Priority != tt.Event.Priority {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Version != tt.Event.Version {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Severity != tt.Event.Severity {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Facility != tt.Event.Facility {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Timestamp != tt.Event.Timestamp {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Hostname != tt.Event.Hostname {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Program != tt.Event.Program {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Pid != tt.Event.Pid {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if evt.Message != tt.Event.Message {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}

		if string(evt.Original) != tt.RawMessage {
			t.Fatalf("Expected: %v\nReceived: %v", tt.Event, evt)
		}
	}
}
