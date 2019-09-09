package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"git.qfpay.net/server/cardinfolink/iso8583"
	"git.qfpay.net/server/cardinfolink/network"
	"git.qfpay.net/server/cardinfolink/sconf"
	"git.qfpay.net/server/goqfpay/logger"
	"github.com/greenboxal/emv-kernel/tlv"
	"os"
	"runtime"
	"time"
)

func testLittleEndian() {

	// 0000 0000 0000 0000   0000 0001 1111 1111
	var testInt uint64 = 256
	fmt.Printf("%d use little endian: \n", testInt)
	var testBytes []byte = make([]byte, 8)
	binary.LittleEndian.PutUint64(testBytes, uint64(testInt))
	//logger.Debugf("uint64 to bytes: %v", testBytes)
	logger.Debugf("%X", testBytes)
	for _, i := range testBytes {
		logger.Debugf("%X", i)
	}

	convInt := binary.LittleEndian.Uint64(testBytes)
	logger.Debugf("bytes to int64: %X", convInt)
}

func test2() {
	s := "0020000000C00012"
	b, _ := hex.DecodeString(s)
	logger.Debugf("%X", b)

	x := binary.LittleEndian.Uint64(b)
	logger.Debugf("%X", x)

	var testBytes []byte = make([]byte, 8)
	binary.LittleEndian.PutUint64(testBytes, x)
	logger.Debugf("%X", testBytes)
}

func test() {
	//var a uint64 = 0x0020000000C00012
	var a uint64 = 0x12000C0000000200
	var buf = make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(a))

	logger.Debugf("buf: %X", buf)
}

func parseEx() {
	bcd8583 := "08000020000000C000120012473538443031313135383837353844303438313635353535001100000001003000023031"
	s8583, _ := hex.DecodeString(bcd8583)
	//b8583 := s8583[:]
	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack([]byte(s8583))
	if err == nil {
		logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		logger.Debugf("self_domain: %X", ups.SelfDomain)
		logger.Debugf("mchntid: %X", ups.MchntId)
	}

}

func test7() {
	x := "DF23818079136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4DF2404C12FCBFA9F0605A0000003339F220101"
	b, _ := hex.DecodeString(x)
	tlv := make(tlv.Tlv)
	err := tlv.DecodeTlv(b)
	if err == nil {
		for k, v := range tlv {
			logger.Debugf("k: %X, v: %X", k, v)
		}
	}

}
func test4() {
	//bcd8583 := "08000000000000C0001030303030303039323031333336323637303131303030310011000000013520"
	//bcd8583 := "08000000000000C0001030303030303039323031333336323637303131303030310011000000013520"
	//bcd8583 := "0810001800000AC000101949560906393530353139303639383037343030303030303030313031333336323637303131303030310011000000013520"
	//bcd8583 := "08000000000000C000143030303030303031303133333632363730313130303031001100000002352001519F0605A0000003339F220101DF23818079136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4DF2404C12FCBFA"
	//bcd8583 := "08000000000000C00014303030303030303130313333363236373031313030303100110000000235200151DF2404C12FCBFA9F0605A0000003339F220101DF23818079136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4"
	bcd8583 := "08000000000000C00014303030303030393230313333363236373031313030303100110000000135000151DF24046772D76F9F0605A000000333DF23818023FED584D4A7B9DC01CBB61747E88A727B846AA30D486F022B88BC0C04A316EB1AFA9D35700711E1A2C0581E9894ED863A361C9AE63A1FBE4430D4634CA55CE8D171AC15B492ED15466AA4C5078CC00A51D08B73CB600ADFA168C682BF6F1A540A7815B7C63DD2DEC16988C682D3CBA3C862E7852796FDC0810E7A752C64A2519F220101"

	s8583, _ := hex.DecodeString(bcd8583)
	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack([]byte(s8583))
	if err == nil {
		logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		logger.Debugf("self_domain: %X", ups.SelfDomain)
		logger.Debugf("mchntid: %X", ups.MchntId)
		logger.Debugf("TParam: %X", ups.TParam)
	}
	tlv := make(tlv.Tlv)
	err = tlv.DecodeTlv([]byte(ups.TParam))
	if err == nil {
		for k, v := range tlv {
			logger.Debugf("k: %X, v: %X", k, v)
		}
	}

}

func test5() {
	a := 128
	s := fmt.Sprintf("%04d", a)
	logger.Debugf("s: %s", s)

	cbcd, _ := hex.DecodeString(s)
	logger.Debugf("bcd: %v", cbcd)
}

func test6() {
	ups := iso8583.ProtoStruct{
		Tid:        "00000092",
		MchntId:    "013362670110001",
		SelfDomain: "00000001352",
	}
	b, err := ups.Pack("0800")
	if err == nil {
		logger.Debugf("b: %X", b)
	}
}

func getDate() (string, string) {
	_, month, day := time.Now().Date()
	hour := time.Now().Hour()
	minute := time.Now().Minute()
	second := time.Now().Second()
	var md = fmt.Sprintf("%02d%02d", month, day)
	var hms = fmt.Sprintf("%02d%02d%02d", hour, minute, second)
	return md, hms
}

func buildHeader() []byte {
	var b []byte
	tpdu := "6001090000"
	header := "600100000000"
	b_tpdu, _ := hex.DecodeString(tpdu)
	b_header, _ := hex.DecodeString(header)
	b = append(b, b_tpdu...)
	b = append(b, b_header...)

	return b
}

func TestGetTmk(rid []byte, index []byte, key []byte, cv []byte) {
	tpdu_header := buildHeader()

	tlv := make(tlv.Tlv)
	tag_9f06 := 0x9F06
	tlv[tag_9f06] = rid
	tag_9f22 := 0x9F22
	tlv[tag_9f22] = index
	tag_df23 := 0xDF23
	tlv[tag_df23] = key
	tag_df24 := 0xDF24
	tlv[tag_df24] = cv
	tp, err := tlv.EncodeTlv()
	if err != nil {
		logger.Debugf("tlv encode: %s", err.Error())
		return
	}
	logger.Debugf("----------------tp: %X", tp)

	ps := iso8583.ProtoStruct{
		Tid:        "00000001",
		MchntId:    "013362670110001",
		SelfDomain: "00000002352",
		TParam:     tp,
	}
	b, err := ps.Pack("0800")
	if err != nil {
		logger.Warnf("pack err: %s", err.Error())
	}
	tpdu_header = append(tpdu_header, b...)
	blen := uint16(len(tpdu_header))
	//xlen := fmt.Sprintf("%x", blen)
	//logger.Debugf("blen: %x", xlen)

	slen := fmt.Sprintf("%04X", blen)
	logger.Debugf("slen: %s", slen)
	bsend, _ := hex.DecodeString(slen)
	//binary.BigEndian.PutUint16(bsend, blen)
	logger.Debugf("%X", bsend)
	bsend = append(bsend, tpdu_header...)

	//bcd := hex.EncodeToString(bsend)
	logger.Debugf("bcd: %X", bsend)

	//gan := "00CD600401000060220000000008000000000000C00014303030303030393230313333363236373031313030303100110000000135000151DF24046772D76F9F0605A000000333DF23818023FED584D4A7B9DC01CBB61747E88A727B846AA30D486F022B88BC0C04A316EB1AFA9D35700711E1A2C0581E9894ED863A361C9AE63A1FBE4430D4634CA55CE8D171AC15B492ED15466AA4C5078CC00A51D08B73CB600ADFA168C682BF6F1A540A7815B7C63DD2DEC16988C682D3CBA3C862E7852796FDC0810E7A752C64A2519F220101"
	//xgan, _ := hex.DecodeString(gan)

	err = network.Mconn.Write(bsend)
	//err = network.Mconn.Write(xgan)
	if err != nil {
		logger.Warnf("write %s", err.Error())
		return
	}
	echo, err := network.Mconn.Read()
	if err != nil {
		logger.Warnf("read %s", err.Error())
		return
	}
	logger.Debugf("%X", echo)

}

func TestGetRsaPubkey() {
	md, hms := getDate()
	logger.Debugf("md: %s hms: %s", md, hms)
	tpdu_header := buildHeader()
	ps := iso8583.ProtoStruct{
		//CardDatetime: hms,
		//CardDate:     md,
		Tid:        "00000001",
		MchntId:    "013362670110001",
		SelfDomain: "00000002352",
	}
	b, err := ps.Pack("0800")
	if err != nil {
		logger.Warnf("pack err: %s", err.Error())
	}

	/*ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack(b)
	if err == nil {
		logger.Debugf("msg_type: %s v: %v", msg_type, ups)
	}*/

	//logger.Debugf("%X", b)
	//sb := hex.EncodeToString(b)
	//logger.Debugf("%s", sb)

	tpdu_header = append(tpdu_header, b...)
	blen := uint16(len(tpdu_header))
	xlen := fmt.Sprintf("%x", blen)
	logger.Debugf("blen: %x", xlen)

	//bsend := make([]byte, 2)
	slen := fmt.Sprintf("%04X", blen)
	logger.Debugf("slen: %s", slen)
	bsend, _ := hex.DecodeString(slen)
	//binary.BigEndian.PutUint16(bsend, blen)
	logger.Debugf("%X", bsend)
	bsend = append(bsend, tpdu_header...)

	//bcd := hex.EncodeToString(bsend)
	logger.Debugf("bcd: %X", bsend)

	err = network.Mconn.Write(bsend)
	if err != nil {
		logger.Warnf("write %s", err.Error())
		return
	}
	echo, err := network.Mconn.Read()
	if err != nil {
		logger.Warnf("read %s", err.Error())
		return
	}
	logger.Debugf("%X", echo)

	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack(echo[11:])
	if err == nil {
		//logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		logger.Debugf("msg_type: %s, tparam: %X", msg_type, ups.TParam)
	}
	tlv := make(tlv.Tlv)
	err = tlv.DecodeTlv([]byte(ups.TParam))
	if err == nil {
		//logger.Debugf("tlv: %v", tlv)
		tag_9f06 := 0x9F06
		logger.Debugf("9F06: %X", tlv[tag_9f06])
		tag_9f22 := 0x9F22
		logger.Debugf("9F22: %X", tlv[tag_9f22])
		tag_df04 := 0xDF04
		logger.Debugf("------DF04: %X", tlv[tag_df04])
		tag_df02 := 0xDF02
		logger.Debugf("------DF02: %X", tlv[tag_df02])

		/*for k, v := range tlv {
			logger.Debugf("k: %X", k)
			logger.Debugf("v: %X", v)
		}*/
	}

	key, _ := hex.DecodeString("79136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4")
	cv, _ := hex.DecodeString("C12FCBFA")
	rid := tlv[0x9F06]
	index := tlv[0x9F22]
	TestGetTmk(rid, index, key, cv)
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()
	arg_num := len(os.Args)
	if arg_num != 2 {
		logger.Warn("input param error")
		return
	}
	var filename = os.Args[1]
	var ret = sconf.Parseconf(filename)

	logger.SetConsole(sconf.Scnf.LogStdOut)
	logger.SetRollingDaily(sconf.Scnf.LogDir, sconf.Scnf.LogFile, sconf.Scnf.LogFileErr)
	loglevel, _ := logger.LoggerLevelIndex(sconf.Scnf.LogLevel)
	logger.SetLevel(loglevel)

	if ret != nil {
		fmt.Printf("ret: %s", ret.Error())
		return
	}

	logger.Debugf("go go go")
	var err error
	//network.Mconn, err = network.NewMyconn("116.236.215.18:5711")
	//network.Mconn, err = network.NewMyconn("116.236.215.18:12164")
	//network.Mconn, err = network.NewMyconn("116.236.215.18:10017")
	network.Mconn, err = network.NewMyconn("116.236.215.18:5811")
	if err != nil {
		logger.Warnf("connet %s", err.Error())
		return
	}
	TestGetRsaPubkey()
	//parseEx()
	//test()
	//test2()
	//testLittleEndian()
	//test4()
	//test5()
	//test6()
	//test7()
}
