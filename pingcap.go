package pingcap

import (
	"fmt"
	"github.com/poofyleek/glog"
	"github.com/poofyleek/pcap"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
)

type ScanResult struct {
	SrcIPAddr  string
	SrcMACAddr string
	SrcVendor  string
}

type PingResult struct {
	IPAddr string
	Status string
}

type PingScanResult struct {
	Type string
	Scan ScanResult
	Ping PingResult
}

func pingAll(CIDR string, ch chan *PingScanResult) []PingResult {
	ip, ipnet, err := net.ParseCIDR(CIDR)
	if err != nil {
		glog.Fatal(err)
	}
	targets := make([]string, 0)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		glog.V(4).Infof("adding %v", ip)
		targets = append(targets, ip.String())
	}
	var wg sync.WaitGroup
	var results []PingResult
	for _, ip := range targets {
		wg.Add(1)
		go func(ipa string) {
			o, err := exec.Command("ping", "-c", "1", "-W", "1", ipa).CombinedOutput()
			out := string(o)
			res := PingResult{}
			res.IPAddr = ipa
			if err != nil {
				if strings.Index(out, "100% packet loss") > 0 {
					res.Status = "absent"
				}
			} else {
				if strings.Index(out, " 0% packet loss") > 0 {
					res.Status = "present"
				} else {
					res.Status = "fuzzy"
					glog.V(2).Infof("%s %v", out, err)
				}
			}
			results = append(results, res)
			psRes := PingScanResult{}
			psRes.Type = "ping"
			psRes.Ping = res
			ch <- &psRes
			wg.Done()
		}(ip)
	}
	wg.Wait()
	return results
}

// From Russ Cox
// http://play.golang.org/p/m8TNTtygK0
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func PingScan(CIDR, OUIFile, dev string, ch chan *PingScanResult) error {
	h, err := pcap.OpenLive(dev, 256, true, 500)
	if err != nil {
		return err
	}
	defer h.Close()
	err = h.SetFilter("icmp")
	if err != nil {
		return err
	}
	var res []PingResult
	go func() {
		res = pingAll(CIDR, ch)
		glog.V(2).Infof("%v", res)
	}()
	ouiDB := make(map[string]string)
	ouiFileExists := true
	f, err := os.OpenFile(OUIFile, os.O_RDONLY, 0666)
	if err != nil {
		ouiFileExists = false
	}
	defer f.Close()
	if ouiFileExists {
		fc, err := ioutil.ReadFile(OUIFile)
		if err == nil {
			lines := strings.Split(string(fc), "\n")
			for _, line := range lines {
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				ouiDB[fields[0]] = strings.Join(fields[1:], " ")
			}
		}
	}
	sres := []ScanResult{}
	// REDFLAG: cannot put this loop in goroutine because of
	// runtime.sigpanic from pkg/runtime/os_linux.c:222
	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r == 0 {
			continue
		}
		pkt.Decode()
		srcVend := "?"
		destVend := "?"
		if len(ouiDB) > 0 {
			srcVend = fmt.Sprintf("%02X%02X%02X",
				pkt.SrcMac&0xff0000000000>>40,
				pkt.SrcMac&0xff00000000>>32,
				pkt.SrcMac&0xff000000>>24)
			srcVend = ouiDB[srcVend]
			destVend = fmt.Sprintf("%02X%02X%02X",
				pkt.DestMac&0xff0000000000>>40,
				pkt.DestMac&0xff00000000>>32,
				pkt.DestMac&0xff000000>>24)
			destVend = ouiDB[destVend]
		}
		glog.V(2).Infof("pkt: ether[%02X:%012X(%s):%012X(%s)] %v",
			pkt.Type, pkt.DestMac, destVend, pkt.SrcMac, srcVend, pkt)
		sr := ScanResult{}
		sr.SrcMACAddr = fmt.Sprintf("%012X", pkt.SrcMac)
		sr.SrcVendor = srcVend
		sr.SrcIPAddr = ""
		var ip *pcap.Iphdr
		for _, h := range pkt.Headers {
			glog.Infof("%v", reflect.TypeOf(h))
			if reflect.TypeOf(h) == reflect.TypeOf(ip) {
				ip = h.(*pcap.Iphdr)
				sr.SrcIPAddr = ip.SrcAddr()
			}
		}
		sres = append(sres, sr)
		psRes := PingScanResult{}
		psRes.Type = "scan"
		psRes.Scan = sr
		ch <- &psRes
	}
	//not reached
	glog.V(2).Infof("exiting pcap capture. %v", h.Geterror())
	return nil
}
