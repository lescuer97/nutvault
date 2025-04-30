package signer

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestConvertionOfBytesToInt(t *testing.T) {
	hexStr := "339efeab"
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(hexStr). %v", err)
	}
	number := binary.BigEndian.Uint32(bytes)

	if number != 866057899 {
		t.Errorf("Bytes where wrongly encoded")
	}
}
