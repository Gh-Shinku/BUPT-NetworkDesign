DNS response 的报文格式，相较于 request 仅仅添加了 Answers 段。
我们这里实现的是功能局限的 DNS 中继服务器，转发当然是可以的，本地解析仅限于将域名解析为 IPv4 地址。

> [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

## response 需要修改 request 的部分：
### Header
#### Flags
* `QR` 需从 query(0) 修改成 response(1)
* `OPCODE` 不用改，还是0
* `AA` 设置成0，表示 not authority
* `TC` 不用改，设置成0表示没有没截断
* `RD` 不用改
* `RA` 不用改
* `Z`  不用改，保留段
* `RCODE` 改为5，表示因政策原因拒绝请求
#### Answer RRs
改成1，只有一个 Answer

### Answers
* `NAME` 指针格式指向 query 中的domain
* `TYPE` 本项目设置成 1，将域名解析为 IPv4 地址
* `CLASS` 本项目设置成 0x0001，表示网络地址
* `TTL` 时延
* `RDLENGTH` RDATA段的长度
* `RDATA` response的内容，取决于TYPE，在本项目中是4个字节的IPv4地址

## 压力测试
使用 dnsperf 进行压测：
```
Statistics:

  Queries sent:         9921
  Queries completed:    8812 (88.82%)
  Queries lost:         1009 (10.17%)
  Queries interrupted:  100 (1.01%)

  Response codes:       NOERROR 8341 (94.66%), SERVFAIL 288 (3.27%), NXDOMAIN 183 (2.08%)
  Average packet size:  request 27, response 65
  Run time (s):         78.800913
  Queries per second:   111.826116

  Average Latency (s):  0.293018 (min 0.010373, max 4.980287)
  Latency StdDev (s):   0.626154
```