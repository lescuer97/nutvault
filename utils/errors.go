package utils

import "errors"

var ErrNoKeysetFound = errors.New("No keyset found")
var ErrAboveMaxOrder = errors.New("Max order is above limit")
