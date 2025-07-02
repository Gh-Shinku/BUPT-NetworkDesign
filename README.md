# BUPT-NetworkDesign

此处实现的是功能局限的 DNS 中继服务器，本地解析仅限于将域名解析为 IPv4 地址。

> [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

## 构建
```
git clone git@github.com:Gh-Shinku/BUPT-NetworkDesign.git
mkdir build && cd build
cmake ..
make
```
需要注意的是，当前在`main.c`中，并未将监听端口设置为 53，实际测试时需要进行修改。

## response 需要修改 request 的部分：
> DNS response 的报文格式，相较于 request 仅仅添加了 Answers 段
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
* `RDATA` response的内容，取决于TYPE，在本项目中是4个字节的 IPv4 地址

## dns_table
dns_table 是一个`g_hash_table`，key 是`char *`，value 是`GArray *`

value 是存储`char *`的动态数组

目前来看，response中的answer(`struct DnsMessageAnswer`类型)中的
`address`成员是`uint32_t`，因此，在插入dns_table之前，需要做一次转换

## 要求：不能引入第三方库
需要重新实现线程池和哈希表，还需要加入对IPv6的支持，TTL延时的处理，LRU 缓存策略

## 压力测试
使用 dnsperf 进行压测：
```
[Version 1 use glib and third thread pool]
Statistics:

  Queries sent:         2997056
  Queries completed:    2997051 (100.00%)
  Queries lost:         5 (0.00%)

  Response codes:       NOERROR 2457621 (82.00%), SERVFAIL 30 (0.00%), NXDOMAIN 3 (0.00%), REFUSED 539397 (18.00%)
  Average packet size:  request 33, response 59
  Run time (s):         60.002875
  Queries per second:   49948.456636

  Average Latency (s):  0.001973 (min 0.000032, max 4.105776)
  Latency StdDev (s):   0.015811

[Version 2 self implemente except thread pool]
dnsperf -s localhost -d testdata.txt -l 60 -p 4090
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s localhost -d testdata.txt -l 60 -p 4090
[Status] Sending queries (to 127.0.0.1:4090)
[Status] Started at: Fri May  2 19:05:04 2025
[Status] Stopping after 60.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         1935031
  Queries completed:    1935031 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 1935031 (100.00%)
  Average packet size:  request 33, response 38
  Run time (s):         60.002351
  Queries per second:   32249.253033

  Average Latency (s):  0.003074 (min 0.000233, max 2.112497)
  Latency StdDev (s):   0.021553

[Version 3 self implemented totally]
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s localhost -d testdata.txt -l 60 -p 4090
[Status] Sending queries (to 127.0.0.1:4090)
[Status] Started at: Sun May  4 22:33:08 2025
[Status] Stopping after 60.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         3707137
  Queries completed:    3707137 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 3707137 (100.00%)
  Average packet size:  request 33, response 35
  Run time (s):         60.001023
  Queries per second:   61784.563240

  Average Latency (s):  0.001585 (min 0.000174, max 2.880180)
  Latency StdDev (s):   0.014155
```

## 说明
简要说明一下DNS中继服务器当前畸形设计的缘由。

DNS 请求有多种类型，正确的缓存做法应当是将"domain + TYPE"作为缓存的key。但由于我初期编写代码时没有把握这一点，导致所有的键都仅仅是 domain。举个例子，在这种情况下，如果缓存了 IPv4 的记录，但是客户端下次请求 IPv6，而服务器认为缓存命中就直接返回 IPv4，导致出现问题。

若要修改这点，项目要改动的地方过多，于是我生硬了地切割了除 IPv4 外所有其他类型的 DNS 请求的缓存。

~~以后也许会填上这个坑（~~
