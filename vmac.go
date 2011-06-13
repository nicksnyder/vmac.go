// Package vmac is a naive, offline implementation of VMAC
// http://fastcrypto.org/vmac/draft-krovetz-vmac-01.txt
package vmac

import (
	"big"
	"bytes"
	"crypto/cipher"
	"crypto/aes"
	"fmt"
	"os"
)

const (
	l1keylen  = 1024
	l1keysize = l1keylen / 8
)

var one = big.NewInt(1)
var m64 = new(big.Int).Lsh(one, 64)                                                                                       // 2^64
var m126 = new(big.Int).Lsh(one, 126)                                                                                     // 2^126
var m128 = new(big.Int).Lsh(one, 128)                                                                                     // 2^128
var p64 = newInt([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF})                                                  // 2^64 - 257
var p64p32 = newInt([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00})                                               // 2^64 - 2^32
var p127 = newInt([]byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // 2^127 - 1

type Hash struct {
	cipher   cipher.Block
	blocklen int
	nonce    []byte
	size     int
	message  *bytes.Buffer
}

func (h *Hash) Write(p []byte) (n int, err os.Error) {
	return h.message.Write(p)
}

func (h *Hash) Sum() []byte {
	hashed := h.vhash()
	pad := h.pdf()
	sum := make([]byte, h.size)
	for i := 0; i < h.size/8; i++ {
		lo := 8 * i
		hi := 8 * (i + 1)
		t := new(big.Int).Add(newInt(pad[lo:hi]), newInt(hashed[lo:hi]))
		t.Mod(t, m64)
		copy(sum[hi-len(t.Bytes()):hi], t.Bytes())
	}
	return sum
}

func (h *Hash) Reset() {
	h.message.Reset()
}

func (h *Hash) Size() int {
	return h.size
}

func (h *Hash) SetNonce(n []byte) os.Error {
	if len(n) >= h.cipher.BlockSize() {
		return nonceSizeError(h.cipher.BlockSize())
	}
	h.nonce = n
	return nil
}

func New(key []byte, nonce []byte, size int) (*Hash, os.Error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) >= cipher.BlockSize() {
		return nil, nonceSizeError(cipher.BlockSize())
	}

	if size%8 != 0 {
		return nil, os.NewError("Size must be a multiple of 8")
	}

	h := new(Hash)
	h.cipher = cipher
	h.blocklen = cipher.BlockSize() * 8
	h.nonce = nonce
	h.size = size
	h.message = bytes.NewBuffer(make([]byte, 0))
	return h, nil
}

func nonceSizeError(n int) os.Error {
	return os.NewError(fmt.Sprintf("Nonce must be less than %d bytes", n))
}

func (h *Hash) vhash() []byte {
	y := make([]byte, 0, h.size)
	for i := 0; i < h.size/8; i++ {
		a := h.l1(i)
		b := h.l2(a, h.message.Len()*8, i)
		c := h.l3(b, i)
		y = append(y, c...)
	}
	return y
}

func (h *Hash) kdf(index, numbits int) []byte {
	n := (numbits + h.blocklen - 1) / h.blocklen // ceil(numbits / blocklen)
	y := make([]byte, n*h.cipher.BlockSize())

	for i := 0; i < n; i++ {
		block := y[i*h.cipher.BlockSize() : (i+1)*h.cipher.BlockSize()]
		block[0] = byte(index)
		block[h.cipher.BlockSize()-1] = byte(i)
		h.cipher.Encrypt(block, block)
	}

	return y[0 : numbits/8]
}

func (h *Hash) pdf() []byte {
	tagsPerBlock := h.cipher.BlockSize() / int(h.size) // for AES tagsPerBlock will be 1 or 2
	mask := byte(tagsPerBlock - 1)                     // assumes tagsPerBlock = 2^i for some integer 0 <= i <= 8
	index := h.nonce[len(h.nonce)-1] & mask

	pad := make([]byte, h.cipher.BlockSize())
	copy(pad[len(pad)-len(h.nonce):], h.nonce)
	pad[len(pad)-1] = pad[len(pad)-1] - index
	h.cipher.Encrypt(pad, pad)

	return pad[int(index)*h.size : int(index)*h.size+h.size]
}

func (h *Hash) l1(iter int) []byte {
	tmpk := h.kdf(128, l1keylen+128*iter)
	k := tmpk[16*iter : l1keysize+16*iter]

	t := (h.message.Len() + l1keysize - 1) / l1keysize // ceil(h.message.Len()/l1keysize)
	y := make([]byte, t*16)

	for i := 0; i < t; i++ {
		var mi []byte
		if h.message.Len() < (i+1)*l1keysize {
			mi = h.message.Bytes()[i*l1keysize:]
		} else {
			mi = h.message.Bytes()[i*l1keysize : (i+1)*l1keysize]
		}
		mi = zeroPad(mi)
		mi = endianSwap(mi)
		nhreturn := nh(k, mi)
		copy(y[i*16:(i+1)*16], nhreturn)
	}
	return y
}

func nh(k, m []byte) []byte {
	t := len(m) / 8
	y := big.NewInt(0)
	for i := 0; i < t; i += 2 {
		mi := newInt(m[i*8 : (i+1)*8])
		ki := newInt(k[i*8 : (i+1)*8])
		mj := newInt(m[(i+1)*8 : (i+2)*8])
		kj := newInt(k[(i+1)*8 : (i+2)*8])
		sumi := new(big.Int).Add(mi, ki)
		sumi.Mod(sumi, m64)
		sumj := new(big.Int).Add(mj, kj)
		sumj.Mod(sumj, m64)
		prod := new(big.Int).Mul(sumi, sumj)
		prod.Mod(prod, m128)
		y.Add(y, prod)
		y.Mod(y, m128)
	}
	y.Mod(y, m126)

	Y := make([]byte, 16)
	copy(Y[16-len(y.Bytes()):], y.Bytes())
	return Y
}

func (h *Hash) l2(m []byte, length, iter int) []byte {
	tmpt := h.kdf(192, 128*(iter+1))
	t := tmpt[16*iter : 16*(iter+1)]
	for i := 0; i < 16; i += 4 {
		t[i] &= 31
	}
	k := newInt(t)
	y := big.NewInt(1)

	n := len(m) / 16
	if n != 0 {
		for i := 0; i < n; i++ {
			mi := newInt(m[16*i : 16*(i+1)])
			y.Mod(y.Add(y.Mul(y, k), mi), p127)
		}
	} else {
		y = k
	}

	y.Add(y, new(big.Int).Lsh(big.NewInt(int64(length%l1keylen)), 64))
	y.Mod(y, p127)

	Y := make([]byte, 16)
	copy(Y[16-len(y.Bytes()):], y.Bytes())
	return Y
}

func (h *Hash) l3(m []byte, iter int) []byte {
	i := 0
	k1 := new(big.Int)
	k2 := new(big.Int)

	for need := iter + 1; need > 0; i++ {
		t := h.kdf(224, 128*(i+1))[16*i : 16*(i+1)]
		k1.SetBytes(t[:8])
		k2.SetBytes(t[8:])
		if k1.Cmp(p64) == -1 && k2.Cmp(p64) == -1 {
			need--
		}
	}

	mint := newInt(m)
	m1 := new(big.Int).Div(mint, p64p32)
	m2 := new(big.Int).Mod(mint, p64p32)

	y := new(big.Int).Add(m1, k1)
	y.Mul(y, new(big.Int).Add(m2, k2))
	y.Mod(y, p64)

	Y := make([]byte, 8)
	copy(Y[8-len(y.Bytes()):], y.Bytes())
	return Y
}

func newInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// Zero pad s to a multiple of 16 bytes
func zeroPad(s []byte) []byte {
	r := len(s) % 16
	if r != 0 {
		t := make([]byte, len(s)+16-r)
		copy(t, s)
		s = t
	}
	return s
}

func endianSwap(s []byte) []byte {
	t := make([]byte, len(s))
	for i := 0; i < len(s); i += 8 {
		t[i] = s[i+7]
		t[i+1] = s[i+6]
		t[i+2] = s[i+5]
		t[i+3] = s[i+4]
		t[i+4] = s[i+3]
		t[i+5] = s[i+2]
		t[i+6] = s[i+1]
		t[i+7] = s[i]
	}
	return t
}
