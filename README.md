# Background

Recently I was experimenting with BGP. Because I was doing unconventional things, the Cisco device I was using rightfully kept complaining and dumping BGP messages on the logs.

It is kinda hard to make out what the BGP hex means with the naked eye past the first 19 bytes. Cisco does not have a public web endpoint to decipher these, so I made my own. A script to dicepher those `BGP-4-MSGDUMP` logs.


# Example Logs
```
%BGP-4-MSGDUMP: unsupported or mal-formatted message received from 10.3.3.3: 
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104 5BA0 00B4 0303 0303 2402 0601 
0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400 068D 
B8
```

```
%BGP-6-MSGDUMP_LIMIT: unsupported or mal-formatted message received from 10.14.41.1: 
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 003F 0200 0000 2740 0101 0040 0212 0204 
0000 07D0 0000 07D0 0000 07D0 0000 07D0 4003 049B 103D 0680 0404 0000 07D0 00
*Sep 16 20:10:37.231: %BGP-6-MALFORMEDATTR: Malformed attribute in (BGP(0) Prefixes: 0.0.0.0/0 ) received from 10.14.41.1
```

```
%BGP-3-NOTIFICATION: sent to neighbor 10.10.10.10 3/1 (update malformed) 188  bytes F0630BB8 00000000 00000000 00000000 00
BGP: 10.10.10.10 Bad attributes FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0118
0200 0000 FD40 0101 0040 0206 0202 0D1C 316E 4003 04C3 10A1 6180 0404 0000 0000 4005 0400 0000 3CC0 081C 0D1C 0002 0D1C 0016 0D1C 0056 0D1C
01F7 0D1C 029A 0D1C 0813 FDE8 FDDE F063 0BB8 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 185D AF90
```


# Usage Examples

## Python

```shell
via 🐍 v3.14.3
❯ python -V
Python 3.14.3

via 🐍 v3.14.3
❯ python msgdmp-to-pcap.py "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104 5BA0 00B4 0303 0303 2402 0601
 0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400 068D
 B8"

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/foo/bgp_dump.pcap
File size       : 159 bytes
Ethernet frame  : 119 bytes
BGP payload     : 65 bytes
BGP message     : OPEN (type 1)
BGP length      : 65 bytes
============================================================
```
