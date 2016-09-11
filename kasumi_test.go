package kasumi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var tests = []struct {
	key    string
	plain  string
	cipher string
}{
	// https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/kasumi/Kasumi-128-64.verified.test-vectors
	{"20000000000000000000000000000000", "0000000000000000", "58C6762606AB2889"},
	{"10000000000000000000000000000000", "0000000000000000", "2FAE2B25507C89C3"},
	{"08000000000000000000000000000000", "0000000000000000", "15D22DA80D43CFEF"},
}

func TestKasumi(t *testing.T) {
	for _, group := range tests {
		var key, pt, ct, dst []byte
		key, _ = hex.DecodeString(group.key)
		pt, _ = hex.DecodeString(group.plain)
		ct, _ = hex.DecodeString(group.cipher)

		cipher, err := NewCipher(key)
		if err != nil {
			t.Errorf(err.Error())
			continue
		}
		if cipher == nil {
			t.Errorf("cipher nil")
		}
		dst = make([]byte, len(ct))
		cipher.Encrypt(dst, pt)
		if !bytes.Equal(dst, ct) {
			t.Errorf("encrypt failed:\ngot : % 02X\nwant: % 02X", dst, ct)
		}

		dst = make([]byte, len(pt))
		cipher.Decrypt(dst, ct)

		if !bytes.Equal(dst, pt) {
			t.Errorf("decrypt failed:\ngot : % 02X\nwant: % 02X", dst, pt)
		}
	}
}
