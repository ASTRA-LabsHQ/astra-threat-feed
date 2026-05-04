package ioc

import "time"

const (
	TypeIPDst  = "ip-dst"
	TypeDomain = "domain"
	TypeMD5    = "md5"
	TypeSHA1   = "sha1"
	TypeSHA256 = "sha256"
)

func Category(t string) string {
	switch t {
	case TypeIPDst, TypeDomain:
		return "Network activity"
	default:
		return "Payload delivery"
	}
}

type IOC struct {
	Value   string
	Type    string
	Source  string
	Comment string
	Tags    []string
	Seen    time.Time
}
