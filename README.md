# dns-sniffer
> dns sniffer network traffic 

### 功能
* 支持dns header解析
* 支持dns query 查询域名解析

### Usage
```
Copyright by jige003

Usage:
    dns-sniffer [-h] -i interface -p port
```

### 日志
```
[*] sniffe on interface: eth0
2019-09-02 15:34:48  172.30.0.17:51082 -> 183.60.83.19:53 [ query ] A www.baidu.com
2019-09-02 15:34:48  172.30.0.17:51082 -> 183.60.83.19:53 [ query ] AAAA www.baidu.com
```

### 参考文档
https://www.ietf.org/rfc/rfc1035.txt
