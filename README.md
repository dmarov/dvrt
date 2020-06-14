netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=10000 connectaddress=127.0.0.1 connectport=10001
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=10000
