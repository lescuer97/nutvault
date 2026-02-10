package utils

import "errors"

var ErrNoKeysetFound = errors.New("no keyset found")
var ErrAboveMaxOrder = errors.New("max order is above limit")
var ErrUnitStringCollision = errors.New("unit string collided")
