# DNS Tunnel Checker #

Basic DNS server checker tool based on a server+client architecture to map out which resource record types are useable over a DNS server. With reasonable knowledge this tool can be used to investigate the network's DNS server and its limitations and determine if DNS tunnelling is an option.


### Usage ###
You must own your own domain which points to your server as it is required with all DNS tunnelling tools.

On the server side, the tool needs to be executed as:
`python main.py -s --domain [example.com]`

Client side:
`python main.py -c --domain [example.com] --nameserver [IP]`


### Steps and techniques ###

* A record - just to check the DNS server
* A record rate limit - to see whether a basic rate limit is in place or not
* A request with CNAME response - check basic functionality
* CNAME record - almost the same as the previous one
* CNAME record rate limit - to see if this record type is rate limited or not
* EDNS support - for longer than 512byte answers
* Long domain name - upstream check, if works than upstream could be used for tunnelling
* Long answer packets - non-EDNS maximum 512byte long packets with a longer domain name
* IPv6 record - with multiple answers. Multiple answers could be used for tunnelling
* TXT record - good for tunnelling
* PRIVATE record - great for tunnelling
* NULL record - great for tunnelling
* MX record - kind of the same as CNAME
* SRV record - kind of the same as CNAME
* DNSKEY record - binary data can be transmitted
* RRSIG record - binary data can be transmitted


