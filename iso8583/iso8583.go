package iso8583

import (
	"errors"
	"fmt"
	"git.qfpay.net/server/goqfpay/logger"
	//"github.com/greenboxal/emv-kernel/tlv"
	"encoding/hex"
	"reflect"
	"strconv"
)

const (
	TAG_BIT         = "bit"
	TAG_LENTYPE     = "lentype"
	TAG_len         = "len"
	TAG_DTYPE       = "dtype"
	TAG_LEFT_ALIGN  = "l_align"
	TAG_RIGHT_ALIGN = "r_align"
	TAG_PADDING_C   = "padding"
)
const (
	FIXEDLENGTH  = iota //固定长度
	VARIABLELEN2        //2位变长
	VARIABLELEN3        //3位变长
)

const (
	ISO8583_HEADER_LEN = 4
	ISO8583_BITMAP_LEN = 8
)

const (
	DATA_TYPE_BCD = iota
	DATA_TYPE_ANS
)

type Bitmap struct {
	Data []byte
}

type ProtoStruct struct {
	//管理类
	Syssn        string `bit:"11" lentype:"0" len:"6" dtype:"0" l_align:"n", r_align:"n",padding:""`
	CardDatetime string `bit:"12" lentype:"0" len:"6" dtype:"0" l_align:"n", r_align:"n",padding:""`
	CardDate     string `bit:"13" lentype:"0" len:"4" dtype:"0" l_align:"n", r_align:"n",padding:""`
	SearchNo     string `bit:"37" lentype:"0" len:"12" dtype:"0" l_align:"n", r_align:"n",padding:""`
	RetCd        string `bit:"39" lentype:"0" len:"2" dtype:"0" l_align:"n", r_align:"n",padding:""`
	Tid          string `bit:"41" lentype:"0" len:"8" dtype:"1" l_align:"n", r_align:"n",padding:""`
	MchntId      string `bit:"42" lentype:"0" len:"15" dtype:"1" l_align:"n", r_align:"n",padding:""`
	SelfDomain   string `bit:"60" lentype:"2" len:"11" dtype:"0" l_align:"n", r_align:"n",padding:""`
	TParam       string `bit:"62" lentype:"2" len:"17" dtype:"1" l_align:"n", r_align:"n",padding:""`
	Opcd         string `bit:"63" lentype:"2" len:"3" dtype:"1" l_align:"n", r_align:"n",padding:""`
	//支付类
}

func (pt *ProtoStruct) packbit(bitmap *Bitmap, num uint) uint64 {
	index, pos := num/8, num%8
	logger.Debugf("bit: %d index: %d pos: %d", num, index, pos)
	if index != 0 {
		index = index
		//8， 16， 24, 32，40, 64bit,字节便宜减1
		if pos == 0 {
			index = index - 1
		}
	}

	if pos != 0 {
		pos = pos - 1
	} else if pos == 0 {
		pos = 7
	}
	bitmap.Data[index] |= 0x80 >> pos
	return 0
}

func (pt *ProtoStruct) getLalign(tv reflect.StructField) bool {
	l_align := tv.Tag.Get(TAG_LEFT_ALIGN)
	if l_align == "y" {
		return true
	}
	return false
}

func (pt *ProtoStruct) getRalign(tv reflect.StructField) bool {
	l_align := tv.Tag.Get(TAG_RIGHT_ALIGN)
	if l_align == "y" {
		return true
	}
	return false
}

func (pt *ProtoStruct) getPadding(tv reflect.StructField) string {
	padding := tv.Tag.Get(TAG_PADDING_C)
	return padding
}

func (pt *ProtoStruct) getTagbit(tv reflect.StructField) uint64 {
	sbit := tv.Tag.Get(TAG_BIT)
	nbit, _ := strconv.Atoi(sbit)
	return uint64(nbit)
}

func (pt *ProtoStruct) getTagFixedLen(tv reflect.StructField) int {
	slen := tv.Tag.Get(TAG_len)
	len, _ := strconv.Atoi(slen)
	return len
}

func (pt *ProtoStruct) getLenType(tv reflect.StructField) int {
	tlen, _ := strconv.Atoi(tv.Tag.Get(TAG_LENTYPE))
	return tlen
}

func (pt *ProtoStruct) getDtype(tv reflect.StructField) int {
	dtype, _ := strconv.Atoi(tv.Tag.Get(TAG_DTYPE))
	return dtype
}

func (pt *ProtoStruct) packVarlen(len int, tv reflect.StructField) (string, error) {
	ltype := pt.getLenType(tv)
	switch ltype {
	case FIXEDLENGTH:
		fixlen := pt.getTagFixedLen(tv)
		if len != fixlen {
			return "", errors.New(fmt.Sprintf("pack fixlenth data error %d!=%d", fixlen, len))
		}
		return "", nil
	case VARIABLELEN2:
		return fmt.Sprintf("%02d", len), nil
	case VARIABLELEN3:
		return fmt.Sprintf("%03d", len), nil
	}
	return "", nil
}

func (pt *ProtoStruct) packDomain(s string, tv reflect.StructField) ([]byte, error) {
	b := []byte{}
	len := len(s)
	dtype := pt.getDtype(tv)
	if dtype == DATA_TYPE_BCD {
		num := len % 2
		//补0, 转BCD
		bcd := []byte{}
		bcd = append(bcd, s...)
		for i := 0; i < num; i++ {
			bcd = append(bcd, "0"...)
		}
		b, _ = hex.DecodeString(string(bcd))
	} else {
		b = append(b, s...)
	}
	logger.Debugf("==b: %X", b)
	ltype := pt.getLenType(tv)
	switch ltype {
	case FIXEDLENGTH:
		/*fixlen := pt.getTagFixedLen(tv)
		if len != fixlen {
			return "", errors.New(fmt.Sprintf("pack fixlenth data error %d!=%d", fixlen, len))
		}*/
		return b, nil
	case VARIABLELEN2:
		slen := fmt.Sprintf("%02d", len)
		blen, _ := hex.DecodeString(slen)
		blen = append(blen, b...)
		return blen, nil
	case VARIABLELEN3:
		slen := fmt.Sprintf("%04d", len)
		blen, _ := hex.DecodeString(slen)
		blen = append(blen, b...)
		return blen, nil
	}
	return nil, errors.New("not support")
}

func (pt *ProtoStruct) hasDomain(domain uint64, bitmap *Bitmap) bool {
	index, pos := domain/8, (8 - domain%8)
	logger.Debugf("check bit %d index %d pos %d", domain, index, pos)
	if index == 8 {
		index = 7
	}
	logger.Debugf("check byte %X", bitmap.Data[index])

	bit := (bitmap.Data[index] >> pos) & 0x01

	if bit == 1 {
		return true
	}
	return false
}

func (pt *ProtoStruct) Setbit(bitmap *Bitmap, tv reflect.StructField) error {
	nbit := pt.getTagbit(tv)
	pt.packbit(bitmap, uint(nbit))
	logger.Debugf("bitmap: %X", bitmap.Data)
	return nil
}

func (pt *ProtoStruct) PackMsgType(s string) ([]byte, error) {
	if len(s) != ISO8583_HEADER_LEN {
		logger.Warnf("pack header error")
		return nil, errors.New("pack msg type error")
	}
	return hex.DecodeString(s)
}

func (pt *ProtoStruct) Pack(header string) ([]byte, error) {
	b := []byte{}
	data := []byte{}
	bitmap := Bitmap{}
	bitmap.Data = make([]byte, 8)

	msg_type, err := pt.PackMsgType(header)
	if err != nil {
		logger.Warnf("pack msg type err: %s", err.Error())
		return nil, err
	}
	data = append(data, msg_type...)
	v_stru := reflect.ValueOf(pt).Elem()
	count := v_stru.NumField()
	logger.Debugf("count=%d", count)
	for i := 0; i < count; i++ {
		item := v_stru.Field(i)
		t_item := v_stru.Type().Field(i)
		logger.Debugf("t_item=%v", t_item)
		nbit := pt.getTagbit(t_item)
		switch item.Kind() {
		case reflect.String:
			s := item.Interface().(string)
			logger.Debugf("s: %s", s)
			if s != "" {
				pt.Setbit(&bitmap, t_item)
				item, err := pt.packDomain(s, t_item)
				if err != nil {
					logger.Warnf("pack %d bit domain %s", nbit, err.Error())
					return b, err
				}
				b = append(b, item...)
			} else {
				logger.Debugf("i=%d|nbit=%d have no data", i, nbit)
				continue
			}
		default:
			return data, errors.New("not support")
		}
	}

	logger.Debugf("bitmap: %X", bitmap.Data)
	data = append(data, bitmap.Data...)
	data = append(data, b...)
	return data, nil
}

func (pt *ProtoStruct) setDomain(b []byte, v reflect.Value, t reflect.StructField, slen int, rlen int) error {
	logger.Debugf("====b: %X slen: %d rlen: %d", b, slen, rlen)
	switch v.Kind() {
	case reflect.String:
		dtype := pt.getDtype(t)
		if dtype == DATA_TYPE_BCD {
			sb := hex.EncodeToString(b)
			v.SetString(sb[0:rlen])
		} else {
			logger.Debugf("get domain: %X", b)
			v.SetString(string(b))
		}
	default:
		return errors.New("not support")
	}
	return nil
}

func (pt *ProtoStruct) unpackLen(bit uint64, b []byte, dlen_type int, start *int, unparsed *int) (int, int, error) {
	switch dlen_type {
	case VARIABLELEN2:
		if *unparsed < 2 {
			return -1, -1, errors.New(fmt.Sprintf("domain %d data error", bit))
		}
		//压缩BCD后一个字节
		s := *start
		e := *start + 1
		slen := b[s:e]
		xlen := hex.EncodeToString(slen)
		len, err := strconv.Atoi(xlen)
		if err != nil {
			logger.Debugf("domain %d parse len error", err.Error())
			return -1, -1, err
		}
		rlen := len
		len = (len + len%2)
		*start += 1
		*unparsed -= 1
		return len, rlen, nil
	case VARIABLELEN3:
		//压缩BCD后压成两个字节
		s := *start
		e := *start + 2
		slen := b[s:e]
		logger.Debugf("slen: %X", slen)
		xlen := hex.EncodeToString(slen)
		logger.Debugf("xlen: %s", xlen)
		len, err := strconv.Atoi(xlen)
		//压缩bcd之后原始数据长度
		rlen := len

		logger.Debugf("len: %d", len)
		if err != nil {
			logger.Debugf("domain %d parse len error", err.Error())
			return -1, -1, err
		}
		*start += 2
		*unparsed -= 2
		//压缩BCD
		len = (len + len%2)
		//返回应该读取的数据长度和原始的数据长度
		return len, rlen, nil

	}
	return -1, -1, errors.New(fmt.Sprintf("domain %d data error", bit))
}

func (pt *ProtoStruct) unpackVarDomain(bit uint64, b []byte, dlen_type int, v reflect.Value, t reflect.StructField, start *int, unparsed *int) error {
	len, rlen, _ := pt.unpackLen(bit, b, dlen_type, start, unparsed)
	dtype := pt.getDtype(t)
	if dtype == DATA_TYPE_BCD {
		len = len / 2
	}
	logger.Debugf("===len: %d", len)

	if len > *unparsed {
		return errors.New(fmt.Sprintf("domain %d data error", bit))
	}

	ddata := b[*start : *start+len]
	err := pt.setDomain(ddata, v, t, len, rlen)
	if err != nil {
		logger.Warnf("domain %d set error %s", bit, err.Error())
	}
	*start += len
	*unparsed -= len
	return err
}

func (pt *ProtoStruct) unpackHeader(b []byte, start *int, unparsed *int) ([]byte, error) {
	xlen := ISO8583_HEADER_LEN / 2
	if *unparsed < xlen {
		return nil, errors.New("unpack header error")
	}
	header := b[*start:xlen]
	*start += xlen
	*unparsed -= xlen

	return header, nil
}

func (pt *ProtoStruct) unpackBitmap(b []byte, start *int, unparsed *int) (*Bitmap, error) {
	if *unparsed < ISO8583_BITMAP_LEN {
		return nil, errors.New("unpack bitmap error")
	}
	b_bitmap := b[*start : *start+ISO8583_BITMAP_LEN]

	logger.Debugf("bitmap: %X", b_bitmap)
	bitmap := Bitmap{}
	bitmap.Data = b_bitmap
	logger.Debugf("%X", bitmap)
	*start += ISO8583_BITMAP_LEN
	*unparsed -= ISO8583_BITMAP_LEN
	return &bitmap, nil
}

func (pt *ProtoStruct) unpackDomain(bit uint64, b []byte, dlen_type int, v reflect.Value, t reflect.StructField, start *int, unparsed *int) error {
	len := pt.getTagFixedLen(t)
	logger.Debugf("parse domain %d struct tag lentype: %d len: %d unparsed: %d", bit, dlen_type, len, *unparsed)
	dtype := pt.getDtype(t)
	if dtype == DATA_TYPE_BCD {
		if len/2 > *unparsed {
			return errors.New(fmt.Sprintf("domain %d bcd data error", bit))
		}
	} else if len > *unparsed {
		return errors.New(fmt.Sprintf("domain %d data error", bit))
	}

	/*if len > *unparsed {
		return errors.New(fmt.Sprintf("domain %d data error", bit))
	}*/

	logger.Debugf("parsed: %X", b[*start:])
	switch dlen_type {
	case FIXEDLENGTH:
		dtype := pt.getDtype(t)
		if dtype == DATA_TYPE_BCD {
			len = len / 2
		}
		logger.Debugf("===len: %d", len)
		//获取定长长度
		ddata := b[*start : *start+len]
		err := pt.setDomain(ddata, v, t, len, len*2)
		if err != nil {
			logger.Warnf("parse %d data err %s", bit, err.Error())
			return err
		}
		*start += len
		*unparsed -= len
		return nil
	case VARIABLELEN2:
		return pt.unpackVarDomain(bit, b, dlen_type, v, t, start, unparsed)
	case VARIABLELEN3:
		return pt.unpackVarDomain(bit, b, dlen_type, v, t, start, unparsed)
	}
	return errors.New(fmt.Sprintf("domain %d data error", bit))
}

func (pt *ProtoStruct) Unpack(b []byte) (string, error) {
	t_unpack := make(map[uint64]reflect.StructField)
	v_unpack := make(map[uint64]reflect.Value)

	v_stru := reflect.ValueOf(pt).Elem()
	count := v_stru.NumField()
	for i := 0; i < count; i++ {
		item := v_stru.Field(i)
		t_item := v_stru.Type().Field(i)
		bit := pt.getTagbit(t_item)
		t_unpack[bit] = t_item
		v_unpack[bit] = item
	}

	start := 0
	unparsed := len(b)

	header, err := pt.unpackHeader(b, &start, &unparsed)
	if err != nil {
		logger.Warnf("%s", err.Error())
		return "", err
	}
	bitmap, err := pt.unpackBitmap(b, &start, &unparsed)
	if err != nil {
		logger.Warnf("%s", err.Error())
		return "", err
	}

	for i := 1; i <= 64; i++ {
		checkbit := uint64(i)
		if pt.hasDomain(checkbit, bitmap) {
			tlen := pt.getLenType(t_unpack[checkbit])
			err := pt.unpackDomain(checkbit, b, tlen, v_unpack[checkbit], t_unpack[checkbit], &start, &unparsed)
			if err != nil {
				logger.Warnf("%s", err.Error())
				return "", err
			}
		} else {
			logger.Debugf("%d have no data", checkbit)
		}
	}
	return hex.EncodeToString(header), nil
}
