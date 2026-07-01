package fingerprint

import "regexp"

func defaultSignatures() []Signature {
	return []Signature{
		// Headers
		{Tech: "ASP.NET", Location: HeaderMatch, Key: "X-Powered-By", Pattern: regexp.MustCompile(`(?i)ASP\.NET`)},
		{Tech: "PHP", Location: HeaderMatch, Key: "X-Powered-By", Pattern: regexp.MustCompile(`(?i)PHP`)},
		{Tech: "Express", Location: HeaderMatch, Key: "X-Powered-By", Pattern: regexp.MustCompile(`(?i)Express`)},
		{Tech: "IIS", Location: HeaderMatch, Key: "Server", Pattern: regexp.MustCompile(`(?i)Microsoft-IIS`)},
		{Tech: "nginx", Location: HeaderMatch, Key: "Server", Pattern: regexp.MustCompile(`(?i)nginx`)},
		{Tech: "Apache", Location: HeaderMatch, Key: "Server", Pattern: regexp.MustCompile(`(?i)Apache`)},

		// Cookies
		{Tech: "Spring", Location: CookieMatch, Key: "JSESSIONID"},
		{Tech: "PHP", Location: CookieMatch, Key: "PHPSESSID"},
		{Tech: "ASP.NET", Location: CookieMatch, Key: "ASP.NET_SessionId"},

		// Body signatures (error pages)
		{Tech: "Spring Boot", Location: BodyMatch, Pattern: regexp.MustCompile(`(?i)Whitelabel Error Page`)},
		{Tech: "Django", Location: BodyMatch, Pattern: regexp.MustCompile(`(?i)Django\s+Page\s+not\s+found`)},
		{Tech: "Laravel", Location: BodyMatch, Pattern: regexp.MustCompile(`(?i)laravel`)},
		{Tech: "Rails", Location: BodyMatch, Pattern: regexp.MustCompile(`(?i)Ruby on Rails`)},
	}
}
