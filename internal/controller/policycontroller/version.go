package policycontroller

import (
	"strings"

	"github.com/alexandremahdhaoui/forge-register/internal/types/regtypes"
)

var (
	CompareVersions = regtypes.CompareVersions
	InPrefix        = regtypes.InPrefix
	IsPrerelease    = regtypes.IsPrerelease
	MajorOf         = regtypes.MajorOf
)

func isPrerelease(version string) bool { return regtypes.IsPrerelease(version) }

func compareTotal(a, b string) int {
	if c := CompareVersions(a, b); c != 0 {
		return c
	}

	return strings.Compare(a, b)
}
