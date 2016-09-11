package kasumi

//@ https://github.com/libtom/libtomcrypt
import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
)

//BlockSize ..
const BlockSize = 8

//KeySize ..
const KeySize = 16

//KeySizeError ..
type KeySizeError int
type kasumi struct {
	key  [KeySize]byte
	kli1 [8]uint32
	koi1 [8]uint32
	kii1 [8]uint32
	kli2 [8]uint32
	koi2 [8]uint32
	kii2 [8]uint32
	koi3 [8]uint32
	kii3 [8]uint32
}

func (*kasumi) BlockSize() int {
	return BlockSize
}

func (k KeySizeError) Error() string {
	return "kasumi: invalid key size " + strconv.Itoa(int(k))
}

//NewCipher ..
func NewCipher(key []byte) (cipher.Block, error) {
	c, err := NewCipherWithRounds(key, 8)
	return c, err
}

//NewCipherWithRounds ..
func NewCipherWithRounds(key []byte, rounds int) (cipher.Block, error) {
	var ukey, kprime [8]uint16
	s := []uint16{0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210}
	l := len(key)
	if l != KeySize {
		return nil, KeySizeError(l)
	}
	e := binary.BigEndian
	c := &kasumi{}
	copy(c.key[:], key)

	for n := 0; n < 8; n++ {
		ukey[n] = e.Uint16(c.key[2*n:])
	}
	for n := 0; n < 8; n++ {
		kprime[n] = ukey[n] ^ s[n]
	}
	for n := 0; n < 8; n++ {
		c.kli1[n] = uint32(_ROL16(ukey[n], 1))
		c.kli2[n] = uint32(kprime[(n+2)&7])
		c.koi1[n] = uint32(_ROL16(ukey[(n+1)&7], 5))
		c.koi2[n] = uint32(_ROL16(ukey[(n+5)&7], 8))
		c.koi3[n] = uint32(_ROL16(ukey[(n+6)&7], 13))
		c.kii1[n] = uint32(kprime[(n+4)&7])
		c.kii2[n] = uint32(kprime[(n+3)&7])
		c.kii3[n] = uint32(kprime[(n+7)&7])
	}

	return c, nil
}

//Encrypt ..
func (c *kasumi) Encrypt(dst, src []byte) {
	var left, right, temp uint32
	if len(dst) < BlockSize || len(src) < BlockSize {
		return
	}
	e := binary.BigEndian
	left = e.Uint32(src)
	right = e.Uint32(src[4:])
	for n := 0; n <= 7; {
		temp = c._FL(left, uint32(n))
		temp = c._FO(temp, uint32(n))
		n++
		right ^= temp
		temp = c._FO(right, uint32(n))
		temp = c._FL(temp, uint32(n))
		n++
		left ^= temp
	}
	e.PutUint32(dst, left)
	e.PutUint32(dst[4:], right)
}

//Decrypt ..
func (c *kasumi) Decrypt(dst, src []byte) {
	var left, right, temp uint32
	if len(dst) < BlockSize || len(src) < BlockSize {
		return
	}
	e := binary.BigEndian
	left = e.Uint32(src)
	right = e.Uint32(src[4:])
	for n := 7; n >= 0; {
		temp = c._FO(right, uint32(n))
		temp = c._FL(temp, uint32(n))
		n--
		left ^= temp

		temp = c._FL(left, uint32(n))
		temp = c._FO(temp, uint32(n))
		n--
		right ^= temp
	}
	e.PutUint32(dst, left)
	e.PutUint32(dst[4:], right)
}

func _ROL16(n uint16, c uint8) uint16 {
	return (n << c) | (n >> (16 - c))
}

func _ROR16(n uint16, c uint8) uint16 {
	return (n >> c) | (n << (16 - c))
}
func _FI(in uint16, subkey uint16) uint16 {
	var nine, seven uint16

	/* The sixteen bit input is split into two unequal halves, *
	 * nine bits and seven bits - as is the subkey            */
	nine = (in >> 7) & 0x1FF
	seven = in & 0x7F
	/* Now run the various operations */
	nine = s9[nine] ^ seven
	seven = s7[seven] ^ (nine & 0x7F)
	seven ^= subkey >> 9
	nine ^= subkey & 0x1FF
	nine = s9[nine] ^ seven
	seven = s7[seven] ^ (nine & 0x7F)
	return (seven << 9) + nine
}
func (c *kasumi) _FO(in uint32, roundno uint32) uint32 {
	var left, right uint16
	/* Split the input into two 16-bit words */

	left = uint16(in >> 16)
	right = uint16(in & 0xFFFF)

	/* Now apply the same basic transformation three times */
	left ^= uint16(c.koi1[roundno])
	left = _FI(left, uint16(c.kii1[roundno]))
	left ^= right

	right ^= uint16(c.koi2[roundno])
	right = _FI(right, uint16(c.kii2[roundno]))
	right ^= left

	left ^= uint16(c.koi3[roundno])
	left = _FI(left, uint16(c.kii3[roundno]))
	left ^= right

	return (uint32(right) << 16) + uint32(left)
}

func (c *kasumi) _FL(in uint32, roundno uint32) uint32 {
	var l, r, a, b uint16
	/* split out the left and right halves */
	l = uint16(in >> 16)
	r = uint16(in) & 0xFFFF
	/* do the FL() operations           */
	a = l & uint16(c.kli1[roundno])
	r ^= _ROL16(a, 1)
	b = r | uint16(c.kli2[roundno])
	l ^= _ROL16(b, 1)
	/* put the two halves back together */

	return (uint32(l) << 16) + uint32(r)
}
