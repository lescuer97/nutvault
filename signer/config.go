package signer

import "time"

type Config struct {
	ExpireTime *time.Time
	AutoRotate bool
}
