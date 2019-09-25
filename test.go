package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"git.qfpay.net/server/cardinfolink/iso8583"
	"git.qfpay.net/server/cardinfolink/network"
	"git.qfpay.net/server/cardinfolink/safe"
	"git.qfpay.net/server/cardinfolink/sconf"
	"git.qfpay.net/server/goqfpay/logger"
	"github.com/greenboxal/emv-kernel/tlv"
	"os"
	"runtime"
	"strings"
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
	//bcd8583 := "02003024048020C280910000000000000010000007421712022000324761340000000019D171210114991787303030303036363430303030303030303030303036363600625049303537030550333039390402303205103030303030323032334B313339373433060630303030313907083346334430333834080839323130202020203135360019323138433235323034202020202020202020200013220002490005004535304135363443"
	//bcd8583 := "0210703E00810AD080121647613400000000190000000000000010000007421629400918171209180008950519003236313136323037333038354130303030303030303130313333363236373031313030303122303030303030303020202030303030303030302020203135360013220002490005000003202020"
	//bcd8583 := "0210703E00810AD080121647613400000000190000000000000010000007421659350918171209180008950519003236313136353037333039344130303030303030303130313333363236373031313030303122303030303030303020202030303030303030302020203135360013220002490005000003202020"
	bcd8583 := "02003024048020C280910000000000000010000007421712022000324761340000000019D171210114991787303030303030303130313333363236373031313030303100625049303537030550333039390402303205103030303030323032334B313339373433060630303030313907083346334430333834080839323130202020203135360019323138433235323034202020202020202020200013220002490005004332323533423633"
	s8583, _ := hex.DecodeString(bcd8583)
	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack([]byte(s8583))
	if err == nil {
		logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		//logger.Debugf("self_domain: %X", ups.SelfDomain)
		//logger.Debugf("mchntid: %X", ups.MchntId)
		//logger.Debugf("AdditionalTradeInfo: %X", ups.AdditionalTradeInfo)
		//logger.Debugf("retcd: %s", ups.RetCd)
	}
	logger.Debugf("%s", ups.ServiceInputCd)
	logger.Debugf("%X", ups.TradeSelfDomain)
}

func testDoTrade() {
	md, hms := getDate()
	logger.Debugf("md: %s hms: %s", md, hms)
	tpdu_header := buildHeader()
	d47 := "5049303537030550333039390402303205103030303030323032334B31333937343306063030303031390708334633443033383408083932313020202020"
	s47, _ := hex.DecodeString(d47)

	d57 := "32313843323532303420202020202020202020"
	s57, _ := hex.DecodeString(d57)

	d64 := "4535304135363443"
	s64, _ := hex.DecodeString(d64)
	ps := iso8583.ProtoStruct{
		TradeCd: "000000",
		Txamt:   "000000010000",
		Syssn:   "000766",
		//CardExpire: "1712",
		CardExpire:     "4912",
		ServiceInputCd: "022",
		ServiceCondCd:  "00",
		//TrackData2:     "4761340000000019D171210114991787",
		//TrackData2:          "8171999927660000D30121212776340005489",
		TrackData2:          "6250944000000772D49121213715950523772",
		Tid:                 "00000001",
		MchntId:             "013362670110001",
		TradeSelfDomain:     s47,
		CurrencyCd:          "156",
		AdditionalTradeInfo: s57,
		SelfDomain:          "2201024900050",
		Mac:                 s64,
	}
	b, err := ps.Pack("0200")
	if err != nil {
		logger.Warnf("pack err: %s", err.Error())
		return
	}
	xb := b[0 : len(b)-8]
	logger.Debugf("=============xb: %X", xb)
	sxb := strings.ToTitle(hex.EncodeToString(xb))
	mak := "2CFEDA51763EC7CE"
	bmak, _ := hex.DecodeString(mak)
	mac := safe.GenMac(sxb, bmak)
	logger.Debugf("=============mac: %s", mac)
	//mac := "80D11E0E9281EA5F"
	xb = append(xb, mac[0:8]...)
	tpdu_header = append(tpdu_header, xb...)
	blen := uint16(len(tpdu_header))
	slen := fmt.Sprintf("%04X", blen)
	logger.Debugf("slen: %s", slen)
	bsend, _ := hex.DecodeString(slen)
	logger.Debugf("%X", bsend)
	bsend = append(bsend, tpdu_header...)
	logger.Debugf("bcd: %X", bsend)

	network.Mconn, err = network.NewMyconn("116.236.215.18:5811")
	if err != nil {
		logger.Warnf("connet %s", err.Error())
		return
	}
	defer network.Mconn.Conn.Close()
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
		logger.Debugf("msg_type: %s v: %v", msg_type, ups)
		//logger.Debugf("self_domain: %X", ups.SelfDomain)
		//logger.Debugf("mchntid: %X", ups.MchntId)
		//logger.Debugf("AdditionalTradeInfo: %X", ups.AdditionalTradeInfo)
		logger.Debugf("retcd: %s", ups.RetCd)
	}
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
		Syssn:      "000007",
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

func TestTmkEffect() {
	tpdu_header := buildHeader()
	ps := iso8583.ProtoStruct{
		Tid:        "00000001",
		MchntId:    "013362670110001",
		SelfDomain: "00000002351",
	}
	b, err := ps.Pack("0800")
	if err != nil {
		logger.Warnf("pack err: %s", err.Error())
	}
	tpdu_header = append(tpdu_header, b...)
	blen := uint16(len(tpdu_header))
	slen := fmt.Sprintf("%04X", blen)
	logger.Debugf("slen: %s", slen)
	bsend, _ := hex.DecodeString(slen)
	logger.Debugf("%X", bsend)
	bsend = append(bsend, tpdu_header...)
	logger.Debugf("bcd: %X", bsend)

	network.Mconn, err = network.NewMyconn("116.236.215.18:5811")
	if err != nil {
		logger.Warnf("connet %s", err.Error())
		return
	}
	defer network.Mconn.Conn.Close()
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
		logger.Debugf("=======msg_type: %s, retcd: %s", msg_type, ups.RetCd)
	}
}

func TestGetTmk(rid []byte, index []byte, key []byte, cv []byte) {
	defer network.Mconn.Conn.Close()
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
		Tid:        "00000001",
		MchntId:    "013362670110001",
		SelfDomain: "00000002352",
	}
	b, err := ps.Pack("0800")
	if err != nil {
		logger.Warnf("pack err: %s", err.Error())
	}
	tpdu_header = append(tpdu_header, b...)
	blen := uint16(len(tpdu_header))
	xlen := fmt.Sprintf("%x", blen)
	logger.Debugf("blen: %x", xlen)

	slen := fmt.Sprintf("%04X", blen)
	logger.Debugf("slen: %s", slen)
	bsend, _ := hex.DecodeString(slen)
	logger.Debugf("%X", bsend)
	bsend = append(bsend, tpdu_header...)
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
		logger.Debugf("msg_type: %s, tparam: %X retcd: %s", msg_type, ups.TParam, ups.RetCd)
	} else {
		return
	}
	tlv := make(tlv.Tlv)
	err = tlv.DecodeTlv([]byte(ups.TParam))
	if err == nil {
		tag_9f06 := 0x9F06
		logger.Debugf("9F06: %X", tlv[tag_9f06])
		tag_9f22 := 0x9F22
		logger.Debugf("9F22: %X", tlv[tag_9f22])
		tag_df04 := 0xDF04
		logger.Debugf("------DF04: %X", tlv[tag_df04])
		tag_df02 := 0xDF02
		logger.Debugf("------DF02: %X", tlv[tag_df02])

	}

	//key, _ := hex.DecodeString("1652F2DB435ABC66869F6AC77E0C339AAD971D837705549BB2D3FF3CB231CD9441BC6695217A3B88E1CDAD0E5499CFCA124CFAF13D4F9FC7C8B0FC11BE17773FAFB47D2B69562EBB7C329779C0FF51A612229CC6908B3B7683316D3A4A819724D2071E88405F24F3F7585D69341BD8D9CAAAA664A1F222D203C8401509519DE1")
	//cv, _ := hex.DecodeString("8D4812F0")
	key, _ := hex.DecodeString("A9635543AAE790C0B27B6165DB1F57AAD9E998ACB704CD3938C29453F54322D8D1AC2C6C117D0C3FEF4420547957787DA8B2FD40723D92A3ECDFA290D62F24341E4E61CFBD418D36C1F7D6562E3AC8EA6CDFE4B9FE1980BDCA136B8DD761E43BF665C0ACB8DE3EEC98006F0824E0A4E885BC188A3396544E5C6EA75EA63984C5")
	cv, _ := hex.DecodeString("5113F151")
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
	//TestTmkEffect()
	//TestSignedUP()
	//parseEx()
	//test()
	//test2()
	//testLittleEndian()
	//test4()
	//test5()
	//test6()
	//test7()
	//test8()
	testDoTrade()
}
