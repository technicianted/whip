package proxy

import (
	"encoding/base64"
	"strings"

	"github.com/technicianted/whip/pkg/logging"
)

func checkAuth(basicAuthHeader []string, username, password string, logger logging.TraceLogger) bool {
	if username == "" || password == "" {
		return true
	}

	if len(basicAuthHeader) == 0 {
		logger.Tracef("proxy auth header not found")
		return false
	}

	reqUsername, reqPassword, ok := parseBasicAuth(basicAuthHeader[0])
	logger.Tracef("basic auth ok: %v, username: %s", ok, username)
	if !ok || reqUsername != username || reqPassword != password {
		return false
	}

	return true
}

// copied from net.http
// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}
