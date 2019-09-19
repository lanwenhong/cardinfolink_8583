package safe

/*
#cgo linux LDFLAGS: -lrt
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

int xordata(char *data1, char *data2, int xorlen)
{

    char *p1 = data1;
    char *p2 = data2;
    char tmp1[2] = {0};
    char tmp2[2] = {0};
    int item1 = 0, item2 = 0;
    int res = 0;
    char check[20] = {0};

    if (xorlen != 16) {
        //ZCWARN("xorlen != 16\n");
        return -1;
    }
    memcpy(check, data1, 16);
    //for (int i = 0; i < xorlen; i++, p1++, p2++) {
	int i;
    for (i = 0; i < xorlen; i++) {
        sprintf(tmp1, "%c", *p1);
        sprintf(tmp2, "%c", *p2);
        item1 = strtoul(tmp1, 0, 16);
        item2 = strtoul(tmp2, 0, 16);
        res = item1 ^ item2;
        sprintf(tmp1, "%X", res);
        *p1 = tmp1[0];
		p1++;
		p2++;
    }
    return 0;
}

//int hmac(char *xorbuf, char *mac)
char * hmac(char *xorbuf)
{
	int slen = strlen(xorbuf);
	char *mac = malloc(17 * sizeof(char));
	char *tmpbuf = malloc((slen +1) * sizeof(char));
	memset(tmpbuf, 0x0, (slen + 1));
	memset(mac, 0x0, 17);
	memcpy(tmpbuf, xorbuf, slen);

	int xorlen = 16*(slen/16+(slen%16?1:0));
	char *xorp = tmpbuf;
	char *nxorp = xorp + 16;

	while(nxorp - tmpbuf < xorlen) {
        if (xordata(xorp, nxorp, 16) == -1) {
            //ZCWARN("xordata error\n");
        }
        nxorp += 16;
    }
    *(tmpbuf + 16) = '\0';
	memcpy(mac, tmpbuf, 16);
	printf("mac: %s\n", mac);
	free(tmpbuf);
	return mac;
}
*/
import "C"
import (
	//"bytes"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

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
	return out, nil
}

func GenMac(data string, makey []byte) string {
	in := C.CString(data)
	out := C.hmac(in)
	mac := C.GoString(out)
	C.free(unsafe.Pointer(in))
	C.free(unsafe.Pointer(out))
	//fmt.Printf("%s\n", mac[:8])
	bhalf := mac[:8]
	bhalf2 := mac[8:]
	bout, _ := encrypt([]byte(bhalf), makey)
	//bcdout := strings.ToTitle(hex.EncodeToString(bout))
	//fmt.Printf("=====bcdout: %s\n", bcdout)
	//bcd_bhalf2 := hex.EncodeToString([]byte(bhalf2))

	bout = append(bout, bhalf2...)
	bcdout := strings.ToTitle(hex.EncodeToString(bout))

	in1 := C.CString(bcdout)
	out2 := C.hmac(in1)
	tmac := C.GoString(out2)
	C.free(unsafe.Pointer(in1))
	C.free(unsafe.Pointer(out2))

	xin, _ := hex.DecodeString(tmac)
	rmac, _ := encrypt(xin, makey)
	hmac := strings.ToTitle(hex.EncodeToString(rmac))
	return hmac
}
