pingcap
=======

![](http://www.progolf.dk/imageserver/getimage.ashx?Imagename=/Files/Images/ecom/ping-kasket-classic-bright-1388673907_102.jpg&w=308&h=378)

A tool to discover machines via ping and packet capture.

It is similar to arpscan.  But not using ARP.

Instead:

1. send out pings to a range specified by CIDR (e.g. 192.168.0.0/24)
2. use pcap to capture incoming packets to learn source ethernet
3. return list discovered machines with IP and Ethernet addr

Usage:

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

Run:

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


Public domain
