package handlers

import (
	"strings"
	"testing"
)

func TestEnsureConfigTxtSetting(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		section    string
		setting    string
		wantChange bool
		wantSubstr string
	}{
		{
			name:       "appends missing section",
			content:    "arm_64bit=1\n",
			section:    "cm5",
			setting:    "dtparam=pciex1_gen=3",
			wantChange: true,
			wantSubstr: "[cm5]\ndtparam=pciex1_gen=3",
		},
		{
			name:       "inserts into existing section",
			content:    "arm_64bit=1\n\n[cm5]\ndtparam=uart0=on\n\n[all]\n",
			section:    "cm5",
			setting:    "dtparam=pciex1_gen=3",
			wantChange: true,
			wantSubstr: "[cm5]\ndtparam=pciex1_gen=3\ndtparam=uart0=on",
		},
		{
			name:       "already present is a no-op",
			content:    "[cm5]\ndtparam=pciex1_gen=3\n",
			section:    "cm5",
			setting:    "dtparam=pciex1_gen=3",
			wantChange: false,
		},
		{
			name:       "same setting in another section does not count",
			content:    "[cm4]\ndtparam=pciex1_gen=3\n",
			section:    "cm5",
			setting:    "dtparam=pciex1_gen=3",
			wantChange: true,
			wantSubstr: "[cm5]\ndtparam=pciex1_gen=3",
		},
		{
			name:       "setting in global scope does not count as sectioned",
			content:    "dtparam=pciex1_gen=3\n",
			section:    "cm5",
			setting:    "dtparam=pciex1_gen=3",
			wantChange: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := ensureConfigTxtSetting(tt.content, tt.section, tt.setting)
			if changed != tt.wantChange {
				t.Fatalf("changed = %v, want %v (result:\n%s)", changed, tt.wantChange, got)
			}
			if tt.wantSubstr != "" && !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("result does not contain %q:\n%s", tt.wantSubstr, got)
			}
			if !tt.wantChange && got != tt.content {
				t.Error("no-op must not modify content")
			}
			// A CM4 section must never gain the setting when targeting cm5.
			if tt.section == "cm5" && strings.Contains(got, "[cm4]") {
				cm4Idx := strings.Index(got, "[cm4]")
				cm5Idx := strings.Index(got, "[cm5]")
				cm4Block := got[cm4Idx:]
				if cm5Idx > cm4Idx {
					cm4Block = got[cm4Idx:cm5Idx]
				}
				if tt.name != "same setting in another section does not count" &&
					strings.Contains(cm4Block, tt.setting) {
					t.Errorf("[cm4] block must not gain the cm5 setting:\n%s", got)
				}
			}
		})
	}
}
