package handlers

import (
	"reflect"
	"testing"
)

func TestServiceActionArgs(t *testing.T) {
	for action, want := range map[string][][]string{
		"":            {{"enable", "--now", "x.service"}},
		"enable_now":  {{"enable", "--now", "x.service"}},
		"start":       {{"start", "x.service"}},
		"restart":     {{"restart", "x.service"}},
		"stop":        {{"stop", "x.service"}},
		"disable_now": {{"disable", "--now", "x.service"}},
		"status":      nil,
	} {
		got, err := serviceActionArgs(action, "x.service")
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("serviceActionArgs(%q) = %v, %v; want %v", action, got, err, want)
		}
	}
	for _, action := range []string{"create", "remove", "Start", " stop"} {
		if _, err := serviceActionArgs(action, "x.service"); err == nil {
			t.Errorf("serviceActionArgs(%q) accepted an unknown action", action)
		}
	}
}
