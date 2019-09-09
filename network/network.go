package network

import (
	"bufio"
	"encoding/hex"
	"git.qfpay.net/server/goqfpay/logger"
	"net"
	"strconv"
	"time"
)

type Myconn struct {
	Conn net.Conn
}

func NewMyconn(addr string) (*Myconn, error) {
	var err error
	mconn := new(Myconn)
	mconn.Conn, err = net.Dial("tcp", addr)
	return mconn, err
}

var Mconn *Myconn = nil

func (mconn *Myconn) Read() ([]byte, error) {
	reader := bufio.NewReader(mconn.Conn)
	head := make([]byte, 2)
	pos := 0
	var err error
	for {
		mconn.Conn.SetDeadline(time.Now().Add(time.Duration(int64(40000)) * time.Millisecond))
		n, err := reader.Read(head[pos:2])
		logger.Debugf("n: %X", n)
		if err != nil {
			logger.Debug("read head error: ", err.Error())
			return nil, err
		}
		pos += n
		if pos == 2 {
			break
		}
	}
	logger.Debugf("head: %X", head)
	slen := hex.EncodeToString(head)
	logger.Debugf("slen: %s", slen)
	//shex := fmt.Sprintf("0x%s", slen)
	blen, err := strconv.ParseUint(slen, 16, 32)
	logger.Debugf("blen: %d", blen)

	//blen := 52
	//blen, err := strconv.Atoi(string(head))
	//blen := binary.BigEndian.Uint16(head)
	data := make([]byte, blen)
	if err != nil {
		logger.Debug("read head len parse error: ", err.Error())
		return nil, err
	}
	pos = 0
	for {
		mconn.Conn.SetDeadline(time.Now().Add(time.Duration(int64(4000)) * time.Millisecond))
		rlen, err := reader.Read(data[pos:blen])
		logger.Debugf("rlen: %d", rlen)
		if err != nil {
			logger.Debugf("read body error: %s", err.Error())
			logger.Debugf("data: %X", data)
			return nil, err
		}
		pos += rlen
		if pos == int(blen) {
			break
		}
	}
	return data, err
}

func (mconn *Myconn) Write(s []byte) error {
	var start int = 0
	for {
		mconn.Conn.SetDeadline(time.Now().Add(time.Duration(int64(5000)) * time.Millisecond))
		n, err := mconn.Conn.Write(s[start:])
		logger.Debugf("write buf: write byte: s:%s writed:%d total:%d ", s, n, len(s))
		if err != nil {
			logger.Warnf("write error! %s", err.Error())
			return err
		}
		start += n
		if start == len(s) {
			break
		}
	}
	return nil
}
