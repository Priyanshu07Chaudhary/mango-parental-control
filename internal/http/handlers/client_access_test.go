package handlers

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/routerarchitects/mango-parental-control/internal/models"
)

func TestValidateTimeRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"00:00:00", true},
		{"07:30:00", true},
		{"23:59:59", true},
		{"12:00:00", true},
		{"00:00:01", true},
		// Invalid formats
		{"24:00:00", false},
		{"7:30:00", false},
		{"07:3:00", false},
		{"07:30:0", false},
		{"07:60:00", false},
		{"07:30:60", false},
		{"", false},
		{"12:00", false},
		{"abc", false},
		{"25:00:00", false},
	}
	for _, tt := range tests {
		got := timeRegex.MatchString(tt.input)
		if got != tt.want {
			t.Errorf("timeRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestClientAccessExtraFieldRejection(t *testing.T) {
	allowed := []string{"client_mac", "start_date", "stop_date", "start_time", "stop_time"}
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			"valid body",
			`{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2026-07-08","stop_date":"2026-07-09","start_time":"07:30:00","stop_time":"08:00:00"}`,
			false,
		},
		{
			"extra field rejected",
			`{"client_mac":"AA:BB:CC:DD:EE:FF","start_date":"2026-07-08","stop_date":"2026-07-09","start_time":"07:30:00","stop_time":"08:00:00","extra":"bad"}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExtraFields([]byte(tt.body), allowed)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExtraFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClientAccessMACTokenRendering(t *testing.T) {
	tests := []struct {
		mac       string
		wantToken string
		wantSec   string
		wantDisp  string
	}{
		{
			"AA:BB:CC:DD:EE:FF",
			"AA_BB_CC_DD_EE_FF",
			"firewall.pc_client_access_AA_BB_CC_DD_EE_FF",
			"PC_ClientAccess_AA_BB_CC_DD_EE_FF",
		},
		{
			"00:11:22:33:44:55",
			"00_11_22_33_44_55",
			"firewall.pc_client_access_00_11_22_33_44_55",
			"PC_ClientAccess_00_11_22_33_44_55",
		},
		{
			"aa:bb:cc:dd:ee:ff",
			"AA_BB_CC_DD_EE_FF",
			"firewall.pc_client_access_AA_BB_CC_DD_EE_FF",
			"PC_ClientAccess_AA_BB_CC_DD_EE_FF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			normalized := normalizeMAC(tt.mac)
			token := strings.ReplaceAll(normalized, ":", "_")
			if token != tt.wantToken {
				t.Errorf("token = %q, want %q", token, tt.wantToken)
			}
			sec := fmt.Sprintf("firewall.pc_client_access_%s", token)
			if sec != tt.wantSec {
				t.Errorf("section = %q, want %q", sec, tt.wantSec)
			}
			disp := fmt.Sprintf("PC_ClientAccess_%s", token)
			if disp != tt.wantDisp {
				t.Errorf("display = %q, want %q", disp, tt.wantDisp)
			}
		})
	}
}

func TestClientAccessMACValidation(t *testing.T) {
	tests := []struct {
		mac    string
		wantOK bool
	}{
		{"AA:BB:CC:DD:EE:FF", true},
		{"aa:bb:cc:dd:ee:ff", true},
		{"00:11:22:33:44:55", true},
		// Invalid MACs
		{"AABBCCDDEEFF", false},
		{"AA-BB-CC-DD-EE-FF", false},
		{"AA:BB:CC:DD:EE", false},
		{"AA:BB:CC:DD:EE:FF:00", false},
		{"GG:HH:II:JJ:KK:LL", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.mac, func(t *testing.T) {
			got := validateMAC(tt.mac)
			if got != tt.wantOK {
				t.Errorf("validateMAC(%q) = %v, want %v", tt.mac, got, tt.wantOK)
			}
		})
	}
}

func TestValidateClientAccessRequest(t *testing.T) {
	baseReq := models.ClientAccessCreateRequest{
		ClientMAC: "AA:BB:CC:DD:EE:FF",
		StartDate: "2036-07-08",
		StopDate:  "2036-07-09",
		StartTime: "07:30:00",
		StopTime:  "08:00:00",
	}

	tests := []struct {
		name       string
		modify     func(*models.ClientAccessCreateRequest)
		now        time.Time
		wantErrSub string
	}{
		{
			name:       "valid request",
			modify:     func(r *models.ClientAccessCreateRequest) {},
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "",
		},
		{
			name:       "missing client_mac",
			modify:     func(r *models.ClientAccessCreateRequest) { r.ClientMAC = "" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "missing start_date",
			modify:     func(r *models.ClientAccessCreateRequest) { r.StartDate = "" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Missing required fields",
		},
		{
			name:       "invalid MAC format",
			modify:     func(r *models.ClientAccessCreateRequest) { r.ClientMAC = "invalid-mac" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Invalid MAC address format",
		},
		{
			name:       "invalid start_date format",
			modify:     func(r *models.ClientAccessCreateRequest) { r.StartDate = "08-07-2036" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Invalid date format",
		},
		{
			name:       "invalid start_time format",
			modify:     func(r *models.ClientAccessCreateRequest) { r.StartTime = "7:30" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Invalid time format",
		},
		{
			name:       "stop_date equal to start_date",
			modify:     func(r *models.ClientAccessCreateRequest) { r.StopDate = "2036-07-08" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_date must be exactly the next calendar date",
		},
		{
			name:       "stop_date two days later",
			modify:     func(r *models.ClientAccessCreateRequest) { r.StopDate = "2036-07-10" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_date must be exactly the next calendar date",
		},
		{
			name:       "stop_time less than start_time (invalid ordering)",
			modify:     func(r *models.ClientAccessCreateRequest) { r.StopTime = "07:00:00" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_time must be strictly greater than start_time",
		},
		{
			name:       "overflow window (stop_time less than start_time)",
			modify:     func(r *models.ClientAccessCreateRequest) { r.StartTime = "23:30:00"; r.StopTime = "00:30:00" },
			now:        time.Date(2036, 7, 8, 0, 0, 0, 0, time.UTC),
			wantErrSub: "stop_time must be strictly greater than start_time",
		},
		{
			name:       "already expired window",
			modify:     func(r *models.ClientAccessCreateRequest) {},
			now:        time.Date(2036, 7, 10, 0, 0, 0, 0, time.UTC),
			wantErrSub: "Cannot create an already expired client-access time window",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := baseReq
			tt.modify(&req)
			err := validateClientAccessRequest(req, tt.now)
			if tt.wantErrSub == "" {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErrSub)
				} else if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErrSub, err)
				}
			}
		})
	}
}
