netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=10000 connectaddress=127.0.0.1 connectport=10001
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=10000


how to disconnect:

run daemon
```
.\ssfd.exe -p 10003 -g
```

run client port forwarder

```
.\ssf.exe -V 192.168.0.101:56641:127.0.0.1:10001 -p 10003 127.0.0.1
```

run netcat to see sent packages, there should be service to send modified packages
```
nc -l -u -p 10001
```
