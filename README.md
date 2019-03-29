# mysocks
A simple and incomplete sock5 protocol implementation，help you see the world over the GFW.

## introduce

This is a simple python program that implement parts of socks5 proxy protocol, I named it my socks.

**require python3.5+ to tun it**

Usage:

```txt
usage: mysocks.py [-h] [-m {local,server}] [--host HOST] [-p PORT]
                  [-H SOCKS5_HOST] [-P SOCKS5_PORT] [-d] -s SECRET [-l LOG]

Help you google~

optional arguments:
  -h, --help            show this help message and exit
  -m {local,server}, --mode {local,server}
                        the run mode, local or server (default: local)
  --host HOST           the ip listen to (default: 0.0.0.0)
  -p PORT, --port PORT  the port listen to (default: 1080 for local and 51080
                        for server)
  -H SOCKS5_HOST, --socks5_host SOCKS5_HOST
                        the socks5 proxy server ip address, this is required
                        while mode is local
  -P SOCKS5_PORT, --socks5_port SOCKS5_PORT
                        the socks5 proxy server listening port (default:
                        51080)
  -d, --daemon          run as daemon (default: False)
  -s SECRET, --secret SECRET
                        the secret key use to run this program, a local server
                        can only communicate to a socks5 server run with the
                        same secret key.
  -l LOG, --log LOG     where to write log file (default: ./darksocks.log)
```

### How to use

#### step 1

Prepare a vps that can visit www.google.com . Assume it's ip is `100.100.100.100`

Run this command on you vps:

```bash
python3 mysocks.py -m server -s mysecretcode -d
```

#### step 2

Run this command on your local machine:

```bash
python3 mysocks.py -s mysecretcode -d -H 100.100.100.100
```

#### step 3

Configure your firefox to use socks5 proxy at 127.0.0.1:1080

Configure your firefox to make the socks5 proxy server do dns for you