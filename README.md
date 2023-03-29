# Exploiting the Heartbleed bug using Go

This simple program tests whether a server is vulnerable to the Heartbleed bug. Tested on [this](https://github.com/gkaptch1/cs558heartbleed) server image (Debian "Jessie")
## Installation
First, to install Go, either run the ```make install``` command or run the following commands
```bash
$ curl -OL https://go.dev/dl/go1.20.2.linux-amd64.tar.gz
$ tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz
$ echo 'export PATH=$PATH:/usr/local/go/bin' >> $HOME/.profile
$ source $HOME/.profile
# Check if Go is properly installed
$ go version 
```

## Usage
Run ```make build``` to build the binary. The program can run with the following interfaces:
```bash
# Scanning Mode
$ ./heartbleed --mode scan --server <server> --port <port>
# Ex-filtration Mode
$ ./heartbleed --mode exfil --server <server> --port <port> --bytes <bytes>
```

## Design
The program first established a TCP connection with the targetted server. Then it sends a Client Hello message which includes the heartbeat extension to enable the functionality at the server. After receiving and parsing the Server Hello messages, the program sends the exploit packet as a heartbeat request, which has a payload length of 65535 bytes and is without a payload. If the server responds to the request, the program deems the server vulnerable to the bug, and if the program is in Ex-filtration mode, it will dump the given number of bytes from the response.


## References
- [How to Exploit the Heartbleed Bug](https://stackabuse.com/how-to-exploit-the-heartbleed-bug/)  
- [SEED Heartbleed Attack Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Heartbleed/Heartbleed.pdf)