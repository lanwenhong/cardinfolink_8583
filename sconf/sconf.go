package sconf

import (
	"git.qfpay.net/server/goqfpay/confparse"
	"git.qfpay.net/server/goqfpay/gconfig"
)

type Sconf struct {
	// log 配置
	LogFile    string `confpos:"log:logfile" dtype:"base"`
	LogFileErr string `confpos:"log:logfile_err" dtype:"base"`
	LogDir     string `confpos:"log:logdir" dtype:"base"`
	LogLevel   string `confpos:"log:loglevel" dtype:"base"`
	LogStdOut  bool   `confpos:"log:logstdout" dtype:"base"`
}

var Scnf *Sconf = new(Sconf)

func Parseconf(filename string) error {
	cfg := gconfig.NewGconf(filename)
	err := cfg.GconfParse()
	if err != nil {
		return nil
	}

	cp := confparse.CpaseNew(filename)
	err = cp.CparseGo(Scnf, cfg)

	return err
}
