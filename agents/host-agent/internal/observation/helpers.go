package observation

import (
	"encoding/json"
	"errors"
	"io"
	"math"
)

func add3(a, b, c uint64) (uint64, bool) {
	if a > math.MaxUint64-b {
		return 0, true
	}
	sum := a + b
	if sum > math.MaxUint64-c {
		return 0, true
	}
	return sum + c, false
}

func multiply(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, true
	}
	return a * b, false
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	}
	return ErrAcceleratorProbe
}
