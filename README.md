pingcap
=======

A tiny tool to discover machines via ping and packet capture.

It is similar to arpscan.  But not using ARP.

Instead:

1. send out pings to a range specified by CIDR (e.g. 192.168.0.0/24)
2. use pcap to capture incoming packets to learn source ethernet
3. return list discovered machines with IP and Ethernet addr

A static x86-64 binary for Linux is under pingscan/ directory.

Running:

```
$ sudo ./pingscan -cidr 10.0.0.0/24  -dev eth0 -timeout 1
```

Example output:
```
{10.0.0.111 00BBCC0BCA3E XYZ CORPORATION}
{10.0.0.222 00AABB984BAC ABC CORPORATION}
...
```

It can also print JSON output.

Usage:
```
sudo ./pingscan
Usage of ./pingscan:
-alsologtostderr=false: log to standard error as well as files
-cidr="": CIDR to scan
-dev="": net device to use
-json=false: output JSON
-log_backtrace_at=:0: when logging hits line file:N, emit a stack trace
-log_dir="": If non-empty, write log files in this directory
-logtostderr=false: log to standard error instead of files
-ouifile="ieee-oui.txt": IEEE OUI database text file
-stderrthreshold=0: logs at or above this threshold go to stderr
-timeout=5: seconds to timeout
-v=0: log level for V logs
-vmodule=: comma-separated list of pattern=N settings for file-filtered logging

```


Building:

You may need to have libpcap-dev on Linux
```
sudo apt-get install libpcap-dev
```

Get the source code:
```
go get github.com/poofyleek/pingcap
```

Go to .../pingcap/

```
go get ./...
```

Go to .../pingcap/pingscan/

```
go build -ldflags '-extldflags "-static"' 
```

Should produce static binary. (ignore warnings about pcap_nametoaddr)...


