package main

import (
	"bytes"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
	"git.qfpay.net/server/cardinfolink/safe"
	//"golang.org/x/crypto/pbkdf2"
)

//ECB PKCS5Padding
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//ECB PKCS5Unpadding
func PKCS5Unpadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//Des加密
func encrypt(origData, key []byte) ([]byte, error) {
	if len(origData) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(origData)%bs != 0 {
		return nil, errors.New("wrong padding")
	}
	out := make([]byte, len(origData))
	dst := out
	for len(origData) > 0 {
		block.Encrypt(dst, origData[:bs])
		origData = origData[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

//Des解密
func decrypt(crypted, key []byte) ([]byte, error) {
	if len(crypted) < 1 || len(key) < 1 {
		return nil, errors.New("wrong data or key")
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(crypted))
	dst := out
	bs := block.BlockSize()
	if len(crypted)%bs != 0 {
		return nil, errors.New("wrong crypted size")
	}

	fmt.Printf("====len: %d\n", len(crypted))
	for len(crypted) > 0 {
		block.Decrypt(dst, crypted[:bs])
		crypted = crypted[bs:]
		dst = dst[bs:]
	}

	return out, nil
}

//[golang ECB 3DES Encrypt]
func TripleEcbDesEncrypt(origData, key []byte) ([]byte, error) {
	tkey := make([]byte, 16, 16)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]
	k3 := tkey[:8]

	/*block, err := des.NewCipher(k1)
	if err != nil {
		return nil, err
	}*/
	//bs := block.BlockSize()
	//origData = PKCS5Padding(origData, bs)

	buf1, err := encrypt(origData, k1)
	if err != nil {
		return nil, err
	}
	fmt.Printf("buf1: %X\n", buf1)
	buf2, err := decrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	fmt.Printf("buf2: %X\n", buf2)
	out, err := encrypt(buf2, k3)
	if err != nil {
		return nil, err
	}
	return out, nil
}

//[golang ECB 3DES Decrypt]
func TripleEcbDesDecrypt(crypted, key []byte) ([]byte, error) {
	tkey := make([]byte, 16, 16)
	copy(tkey, key)
	k1 := tkey[:8]
	k2 := tkey[8:16]
	k3 := tkey[:8]
	buf1, err := decrypt(crypted, k3)
	if err != nil {
		return nil, err
	}
	fmt.Printf("buf1: %X\n", buf1)
	buf2, err := encrypt(buf1, k2)
	if err != nil {
		return nil, err
	}
	out, err := decrypt(buf2, k1)
	if err != nil {
		return nil, err
	}
	//out = PKCS5Unpadding(out)
	return out, nil
}

func main() {
	tmk := "8A6B0BC7E62A98A82AB0257AD3A8B5A4"
	btmk, _ := hex.DecodeString(tmk)
	//mak := "3701856F23EE0CD1"
	mak := "4A5437EC854CDA49"
	bmak, _ := hex.DecodeString(mak)

	//x := []byte("你中了女神徐莉的毒，唯一解锁的方式是和她在一起。")
	//key := []byte("87654321hgfedcbaopqrstuv")
	//x1, _ := TripleEcbDesEncrypt(x, key)
	//x2, _ := TripleEcbDesDecrypt(bmak, btmk)
	x2, _ := TripleEcbDesEncrypt(bmak, btmk)
	fmt.Printf("%X\n", x2)

	data := "02003024048020C280910000000000000100000007571712022000324761340000000019D171210114991787303030303030303130313333363236373031313030303100625049303537030550333039390402303205103030303030323032334B31333937343306063030303031390708334633443033383408083932313020202020313536001932313843323532303420202020202020202020001322010249000500"

	x := safe.GenMac(data, bmak)
	fmt.Printf("=====mac: %s\n", x)
}
