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

func TestGetRsaPubkey() {
	md, hms := getDate()
	logger.Debugf("md: %s hms: %s", md, hms)
	tpdu_header := buildHeader()
	ps := iso8583.ProtoStruct{
		CardDatetime: hms,
		CardDate:     md,
		Tid:          "30131990",
		MchntId:      "013102258120001",
		SelfDomain:   "00000001352",
	}
	b, err := ps.Pack("0800")
	if err != nil {
		logger.Warnf("pack err: %s", err.Error())
	}

	ups := iso8583.ProtoStruct{}
	msg_type, err := ups.Unpack(b)
	if err == nil {
		logger.Debugf("msg_type: %s v: %v", msg_type, ups)
	}

	//logger.Debugf("%X", b)
	sb := hex.EncodeToString(b)
	logger.Debugf("%s", sb)
	tpdu_header = append(tpdu_header, b...)
	blen := uint16(len(tpdu_header))
	logger.Debugf("blen: %d", blen)

	bsend := make([]byte, 2)
	binary.BigEndian.PutUint16(bsend, blen)
	logger.Debugf("%v", bsend)
	bsend = append(bsend, tpdu_header...)

	bcd := hex.EncodeToString(bsend)
	logger.Debugf("bcd: %s", bcd)

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
	network.Mconn, err = network.NewMyconn("116.236.215.18:5711")
	if err != nil {
		logger.Warnf("connet %s", err.Error())
		return
	}
	//TestGetRsaPubkey()
	parseEx()
	//test()
	//test2()
	//testLittleEndian()
}
