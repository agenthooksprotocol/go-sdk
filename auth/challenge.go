package auth

import (
	"net/http"
	"strings"

	"github.com/agenthooksprotocol/go-sdk/internal/authutil"
)

func insufficientScope(response *http.Response) bool {
	if response.StatusCode != http.StatusForbidden {
		return false
	}
	challenges, ok := authutil.ParseWWWAuthenticate(strings.Join(response.Header.Values("WWW-Authenticate"), ","))
	if !ok {
		return false
	}
	found := false
	for _, challenge := range challenges {
		if strings.EqualFold(challenge.Scheme, "Bearer") {
			// Multiple Bearer challenges are ambiguous for scope escalation.
			if found || challenge.Params["error"] != "insufficient_scope" {
				return false
			}
			found = true
		}
	}
	return found
}
