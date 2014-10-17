package main

import (
	"flag"
	"fmt"
	"github.com/poofyleek/glog"
	"github.com/poofyleek/pingcap"
	"os"
	"time"
)

func main() {
	var CIDR, dev, OUIFile string
	var timeout int64

	flag.StringVar(&CIDR, "cidr", "", "CIDR to scan")
	flag.StringVar(&OUIFile, "ouifile", "ieee-oui.txt", "IEEE OUI database text file")
	flag.StringVar(&dev, "dev", "", "net device to use")
	flag.Int64Var(&timeout, "timeout", 5, "seconds to timeout")
	flag.Parse()
	if dev == "" || CIDR == "" {
		flag.Usage()
		os.Exit(1)
	}
	ch := make(chan *pingcap.PingScanResult, 1)
	startTime := time.Now().Unix()
	go func() {
		for {
			time.Sleep(time.Second)
			if (time.Now().Unix() - startTime) > timeout {
				glog.V(2).Infof("stopping after %d seconds.", timeout)
				os.Exit(1)
			}
		}
	}()
	go func() {
		for {
			res := <-ch
			if res.Type == "scan" {
				fmt.Println(res.Scan)
			}
		}
	}()
	err := pingcap.PingScan(CIDR, OUIFile, dev, ch)
	if err != nil {
		panic(err)
	}
}
