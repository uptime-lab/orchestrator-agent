package handlers

import "fmt"

// serviceActionArgs maps a manage_service action to the systemctl invocations
// it runs; "status" runs none (the handler only reads the unit's state). An
// empty action means enable_now. Build-tag-free so the mapping is tested on
// every platform.
func serviceActionArgs(action, unit string) ([][]string, error) {
	switch action {
	case "enable_now", "":
		return [][]string{{"enable", "--now", unit}}, nil
	case "start":
		return [][]string{{"start", unit}}, nil
	case "restart":
		return [][]string{{"restart", unit}}, nil
	case "stop":
		return [][]string{{"stop", unit}}, nil
	case "disable_now":
		return [][]string{{"disable", "--now", unit}}, nil
	case "status":
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown service action %q", action)
	}
}
