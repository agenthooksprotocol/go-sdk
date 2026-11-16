package authutil

import "strings"

// Challenge is one parsed HTTP authentication scheme and its parameters.
type Challenge struct {
	Scheme string
	Params map[string]string
}

// ParseWWWAuthenticate accepts RFC 9110 auth-params and token68 credentials.
// A token68 is recognized only when it consumes the whole credential segment;
// padding must not be mistaken for an auth-param assignment.
func ParseWWWAuthenticate(header string) ([]Challenge, bool) {
	if len(header) > 65536 || strings.ContainsAny(header, "\r\n") {
		return nil, false
	}
	var out []Challenge
	i := 0
	space := func() {
		for i < len(header) && (header[i] == ' ' || header[i] == '\t') {
			i++
		}
	}
	token := func() string {
		start := i
		for i < len(header) && authToken(header[i]) {
			i++
		}
		return header[start:i]
	}
	for {
		space()
		for i < len(header) && header[i] == ',' {
			i++
			space()
		}
		if i == len(header) {
			return out, true
		}
		scheme := token()
		if scheme == "" {
			return nil, false
		}
		challenge := Challenge{Scheme: scheme, Params: make(map[string]string)}
		if i == len(header) || header[i] == ',' {
			out = append(out, challenge)
			continue
		}
		if header[i] != ' ' && header[i] != '\t' {
			return nil, false
		}
		space()
		// RFC token68 permits trailing '=' padding but no embedded padding.
		end := i
		for end < len(header) && header[end] != ',' {
			end++
		}
		if ValidBearer(strings.Trim(header[i:end], " \t")) {
			i = end
			out = append(out, challenge)
			continue
		}
		for {
			name := strings.ToLower(token())
			space()
			if name == "" || i == len(header) || header[i] != '=' {
				return nil, false
			}
			i++
			space()
			value := ""
			if i < len(header) && header[i] == '"' {
				i++
				var b strings.Builder
				closed := false
				for i < len(header) {
					ch := header[i]
					i++
					if ch == '"' {
						closed = true
						break
					}
					if ch == '\\' {
						if i == len(header) {
							return nil, false
						}
						ch = header[i]
						i++
					}
					if (ch < 32 && ch != '\t') || ch == 127 {
						return nil, false
					}
					b.WriteByte(ch)
				}
				if !closed {
					return nil, false
				}
				value = b.String()
			} else {
				value = token()
				if value == "" {
					return nil, false
				}
			}
			if _, exists := challenge.Params[name]; exists {
				return nil, false
			}
			challenge.Params[name] = value
			space()
			if i == len(header) {
				out = append(out, challenge)
				return out, true
			}
			if header[i] != ',' {
				return nil, false
			}
			i++
			space()
			// After a comma, a token followed by '=' continues this parameter list.
			saved := i
			_ = token()
			space()
			parameter := i < len(header) && header[i] == '='
			i = saved
			if !parameter {
				break
			}
		}
		out = append(out, challenge)
	}
}

func authToken(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}
