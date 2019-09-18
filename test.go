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
	//x := "DF23818079136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4DF2404C12FCBFA9F0605A0000003339F220101"
	//x := "9F0605A0000003339F220101DF23818027B328E6804401B9E2AAD22CFD3316B89A69C9F2238785599AC1DE66AE081251E041A5E8F4763FA75C5DAEE8C948A4FE2B69F9F0752867D82E7189C51C180D0C4050C33E92046E6E62FD86C73183E2AEF94F723366EDE5ED964522EB8ECB60966D0F62ADE6F12060F2944FB571BC8677F8AC03BB0E3DC4CD7090097B464392E5DF24048F73AE16"
	//x := "303537030550333039390402303205103030303030323032334B31333937343306063030303031390708334633443033383408083932313020202020"
	s := "PI"
	logger.Debugf("xb: %X", s)
	//x := "5049 303537 030550333039390402303205103030303030323032334B31333937343306063030303031390708334633443033383408083932313020202020"
	x := "030550333039390402303205103030303030323032334B31333937343306063030303031390708334633443033383408083932313020202020"
	b, _ := hex.DecodeString(x)
	logger.Debugf("len b: %d", len(b))
	//logger.Debugf("b: %s", string(b))
	tlv := make(tlv.Tlv)
	err := tlv.DecodeTlv(b)
	if err == nil {
		for k, v := range tlv {
			logger.Debugf("k: %X, v: %s", k, string(v))
		}
	}

}

func test8() {
	bcd8583 := "02003024048020C280910000000000000010000007421712022000324761340000000019D171210114991787303030303036363430303030303030303030303036363600625049303537030550333039390402303205103030303030323032334B313339373433060630303030313907083346334430333834080839323130202020203135360019323138433235323034202020202020202020200013220002490005004535304135363443"
	s8583, _ := hex.DecodeString(bcd8583)
	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack([]byte(s8583))
	if err == nil {
		logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		logger.Debugf("self_domain: %X", ups.SelfDomain)
		logger.Debugf("mchntid: %X", ups.MchntId)
		logger.Debugf("AdditionalTradeInfo: %X", ups.AdditionalTradeInfo)
	}
	logger.Debugf("%s", ups.ServiceInputCd)
	logger.Debugf("%X", ups.TradeSelfDomain)
}

func testDoTrade() {
	md, hms := getDate()
	logger.Debugf("md: %s hms: %s", md, hms)
	//tpdu_header := buildHeader()
	d47 := "5049303537030550333039390402303205103030303030323032334B31333937343306063030303031390708334633443033383408083932313020202020"
	s47, _ := hex.DecodeString(d47)

	d57 := "32313843323532303420202020202020202020"
	s57, _ := hex.DecodeString(d57)

	d64 := "4535304135363443"
	s64, _ := hex.DecodeString(d64)
	ps := iso8583.ProtoStruct{
		TradeCd:             "000000",
		Txamt:               "000000001000",
		Syssn:               "000742",
		CardExpire:          "1712",
		ServiceInputCd:      "0220",
		ServiceCondCd:       "00",
		TrackData2:          "4761340000000019D171210114991787",
		Tid:                 "00000664",
		MchntId:             "000000000000666",
		TradeSelfDomain:     s47,
		CurrencyCd:          "156",
		AdditionalTradeInfo: s57,
		SelfDomain:          "2200024900050",
		Mac:                 s64,
	}
	b, err := ps.Pack("0200")
	if err != nil {
		logger.Warnf("pack err: %s", err.Error())
		return
	}
	logger.Debugf("b: %X", b)
}

func test4() {
	//bcd8583 := "08000000000000C0001030303030303039323031333336323637303131303030310011000000013520"
	//bcd8583 := "08000000000000C0001030303030303039323031333336323637303131303030310011000000013520"
	//bcd8583 := "0810001800000AC000101949560906393530353139303639383037343030303030303030313031333336323637303131303030310011000000013520"
	//bcd8583 := "08000000000000C000143030303030303031303133333632363730313130303031001100000002352001519F0605A0000003339F220101DF23818079136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4DF2404C12FCBFA"
	//bcd8583 := "08000000000000C00014303030303030303130313333363236373031313030303100110000000235200151DF2404C12FCBFA9F0605A0000003339F220101DF23818079136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4"
	bcd8583 := "08000000000000C00014303030303030393230313333363236373031313030303100110000000135000151DF24046772D76F9F0605A000000333DF23818023FED584D4A7B9DC01CBB61747E88A727B846AA30D486F022B88BC0C04A316EB1AFA9D35700711E1A2C0581E9894ED863A361C9AE63A1FBE4430D4634CA55CE8D171AC15B492ED15466AA4C5078CC00A51D08B73CB600ADFA168C682BF6F1A540A7815B7C63DD2DEC16988C682D3CBA3C862E7852796FDC0810E7A752C64A2519F220101"
	//bcd8583 := "08000000000000C000143030303030303031303133333632363730313130303031001100000001350003029F0605A0000003339F220101DF238180C8AFFD08EBF68514EF63DE09C3A469D1607B703C21F0E62FD2229E056502BD9CDED4937780DAD1245096621D0F57C7DF5DAA156E480E4DD725155CEC2154941580E085D1B6C0DA6B894EDCACB8BB0B5CF2BAA9884F8A8CC54B8E83665BFC75ECD6CBF9BCCA3D6575A8C25484DA44E7BCF6D93B8652041A7961DE32D388F96544DF240478B558C7"

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

func TestSignedUP() {
	tpdu_header := buildHeader()
	ps := iso8583.ProtoStruct{
		Tid:        "00000001",
		MchntId:    "013362670110001",
		SelfDomain: "00000001003",
		Syssn:      "000006",
		Opcd:       "003",
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

	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack(echo[11:])
	if err == nil {
		//logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		//logger.Debugf("msg_type: %s, tparam: %X", msg_type, ups.TParam)
		logger.Debugf("msg_type: %s, AcceptorCd: %s, tparam: %X retcd: %s", msg_type, ups.AcceptorCd, ups.TParam, ups.RetCd)
	}
}

func TestGetTmk(rid []byte, index []byte, key []byte, cv []byte) {
	tpdu_header := buildHeader()

	tlv1 := make(tlv.Tlv)
	tag_9f06 := 0x9F06
	tlv1[tag_9f06] = rid
	tag_9f22 := 0x9F22
	tlv1[tag_9f22] = index
	tag_df23 := 0xDF23
	tlv1[tag_df23] = key
	tag_df24 := 0xDF24
	tlv1[tag_df24] = cv
	tp, err := tlv1.EncodeTlv()
	if err != nil {
		logger.Debugf("tlv encode: %s", err.Error())
		return
	}
	logger.Debugf("----------------tp: %X", tp)

	ps := iso8583.ProtoStruct{
		Tid:        "00000001",
		MchntId:    "013362670110001",
		SelfDomain: "00000002350",
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

	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack(echo[11:])
	if err == nil {
		//logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		//logger.Debugf("msg_type: %s, tparam: %X", msg_type, ups.TParam)
		logger.Debugf("=======msg_type: %s, tparam: %X retcd: %s", msg_type, ups.TParam, ups.RetCd)
	}

	xtlv := make(tlv.Tlv)
	err = xtlv.DecodeTlv([]byte(ups.TParam))
	if err == nil {
		for k, v := range xtlv {
			logger.Debugf("k: %X v: %X", k, v)
		}
	}

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
		logger.Debugf("msg_type: %s, tparam: %X retcd: %s", msg_type, ups.TParam, ups.RetCd)
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

	//key, _ := hex.DecodeString("79136CDE3F9EE18C893450C5BF4DD63DA4FF7D7279828212C9647F5F9F7029BECA06E953EB19F1F80DB503877181523BD9EABA879E29AE8CE96EFE65FF6567C9BE4B6F2F9AC4D40DF803AC998E5112E9AA4E68D0669A279679C5FD123C2D6012ACFF5DE69F18FB03A7D9EE62B0388FDD4134F91115A140520907190B66A07FC4")
	//cv, _ := hex.DecodeString("C12FCBFA")
	//key, _ := hex.DecodeString("0E9AE93364D0D3799C1716E94946C4B86BAE5D3570323E87453B5B4F8FCB71117DE841A243755AA71A575CCC2FAB30DA64F5E9B102607015D02233CA217E14F608BB7A195EEF468CFF902CF3F15C05F662F1F6F6912124FCF8F3E1F85BB74322D6A1673D4E926E8902A5BF6DBAFE51608264940CB291BCD0FB2695C2182C010F")
	//cv, _ := hex.DecodeString("77EFD094")

	key, _ := hex.DecodeString("C2DC0AF0464A2F6E08BE54A11FF92A47B0418BE42DDE1FED55F6976951C9299E886EDC97D39AF1643C44CA69E13190ED847C8E4D57D2EC07936EB87D6C6453CE782E09F9362748ED99470C27001D3FB548FC23AF8D4A8CF12960639741F6AAADC6A7AB3311873108CD972538EC907C954713F0EB5202802A824D79D1C5628EB6")
	//key, _ := hex.DecodeString("52E7CED136BF4D4F4E8729D503D06F95DF6DE4087D4EB86B76635B9B7548E2CA4F5EFEC58344E17E8475FD5F0BAB192EE32C5EC5B17025327E8B2354F3E4C530F31339841754C7092C31B7678CEB0C12F9A9B52D42702D5F44FD05102CFBF6EEFA78D9DC143DB8C5451A296981E0C19C483E2358D43F2DD85DFC26D92FD55B5A")
	//key, _ := hex.DecodeString("709619BB142717E3D509FACC2F13FF8A5753D558CFA30A406B66F5F5CB1C7D595190D62E4ABCD3823096B70F4DB737DB62F89E0A5F655281647FE5E7D900044201189DB6A26F70ADF39BF04B3952AE28C3376EB02754D49A09F39936379A5E6FF9AA956B128291ED18C4B7A0A5B8499901AE4FF53DC15CCE9A5439C93A445B8C")
	cv, _ := hex.DecodeString("400D1173")
	rid := tlv[0x9F06]
	index := tlv[0x9F22]
	network.Mconn.Conn.Close()
	network.Mconn, err = network.NewMyconn("116.236.215.18:5811")
	if err != nil {
		logger.Warnf("connet %s", err.Error())
		return
	}

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
	//TestGetRsaPubkey()
	//TestSignedUP()
	//parseEx()
	//test()
	//test2()
	//testLittleEndian()
	//test4()
	//test5()
	//test6()
	//test7()
	test8()
	//testDoTrade()
}
