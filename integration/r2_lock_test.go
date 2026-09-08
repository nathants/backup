package integration

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestR2LockCoverageUsesBackupNamespace(t *testing.T) {
	for _, test := range []struct {
		name       string
		prefix     string
		rulePrefix string
		disabled   bool
		condition  string
		accepted   bool
	}{
		{name: "probe stem only", prefix: "repository", rulePrefix: "repository/contract-"},
		{name: "exact probe only", prefix: "repository", rulePrefix: "repository/contract-fixture/"},
		{name: "namespace", prefix: "repository", rulePrefix: "repository/", accepted: true},
		{name: "broader literal prefix", prefix: "repository", rulePrefix: "repository", accepted: true},
		{name: "parent namespace", prefix: "tenant/repository", rulePrefix: "tenant/", accepted: true},
		{name: "bucket rule covers namespace", prefix: "repository", accepted: true},
		{name: "sibling namespace", prefix: "repository", rulePrefix: "repository-other/"},
		{name: "objects only", prefix: "repository", rulePrefix: "repository/objects/"},
		{name: "disabled", prefix: "repository", disabled: true},
		{name: "finite retention", prefix: "repository", condition: "Age"},
		{name: "bucket namespace", accepted: true},
		{name: "bucket probe only", rulePrefix: "contract-"},
		{name: "bucket namespace is not slash", rulePrefix: "/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rule := r2LockRule{ID: "fixture", Enabled: !test.disabled, Prefix: test.rulePrefix}
			rule.Condition.Type = test.condition
			if rule.Condition.Type == "" {
				rule.Condition.Type = "Indefinite"
			}
			data, err := json.Marshal(rule)
			if err != nil {
				t.Fatal(err)
			}
			err = validateR2LockCoverage(cloudContractConfig{prefix: test.prefix}, []json.RawMessage{data})
			if (err == nil) != test.accepted {
				t.Fatalf("backup namespace %q under rule %q: err=%v; want accepted=%t", test.prefix, test.rulePrefix, err, test.accepted)
			}
		})
	}
}

func TestR2LockCoverageStillValidatesEveryRule(t *testing.T) {
	valid := json.RawMessage(`{"id":"all","enabled":true,"prefix":"","condition":{"type":"Indefinite"}}`)
	for _, malformed := range []json.RawMessage{
		json.RawMessage(`{`),
		json.RawMessage(`{"enabled":true,"prefix":"","condition":{"type":"Indefinite"}}`),
		json.RawMessage(`{"id":"missing-condition","enabled":true,"prefix":""}`),
	} {
		err := validateR2LockCoverage(cloudContractConfig{prefix: "repository"}, []json.RawMessage{valid, malformed})
		if err == nil {
			t.Fatalf("malformed rule after a covering rule was accepted: %s", malformed)
		}
	}
	if err := validateR2LockCoverage(cloudContractConfig{prefix: "repository"}, nil); err == nil || !strings.Contains(err.Error(), "no enabled indefinite") {
		t.Fatalf("missing lock rules were accepted: %v", err)
	}
}
