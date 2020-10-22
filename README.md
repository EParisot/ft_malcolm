# ft_malcolm
An introduction to Man in the Middle attacks

## usage:
```
usage: ./ft_malcolm src_IP src_MAC tgt_IP tgt_MAC [-i iface] [-t sec] [-s] [-b]
	iface:   network interface (str)
	src_IP:  host IP (XXX.XXX.XXX.XXX or hostname))
	src_MAC: host MAC (XX:XX:XX:XX:XX:XX)
	tgt_IP:  target IP (XXX.XXX.XXX.XXX or hostname)
	tgt_MAC: target MAC (XX:XX:XX:XX:XX:XX)
	-t sec:  timeout seconds to wait for reply
	-s:      wait for specific IP source
	-b:      send bi-directional spoof
```
