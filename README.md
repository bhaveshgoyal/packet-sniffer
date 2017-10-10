# packet-sniffer
A sniffer program written in C, that lets you Capture and Filter packets in promiscuous mode over a specified interface.
The program uses libpcap library to provide support to sniff and filter packets using BPF filters.
In addition, the program provides support to read a precaptured pcap dump and also filter payloads based on a specified string.

### To run:
```
Ensure you have libpcap library installed
sudo apt-get install libpcap-dev

git clone https://github.com/bhaveshgoyal/packet-sniffer.git
cd packet-sniffer/
make
chmod +x ./sniffer
./sniffer -i [interface] -r [input file] -s [payload search string] [filter expression]
```

[filter expression] is a BPF filter that specifies which packets will be dumped. If no filter is given, all packets seen on the interface (or contained in the
trace) are dumped.
For each packet, the program prints a record containing the timestamp, source and destination MAC address, EtherType, packet length, source and destination IP
address and port, protocol type and the raw content of the packet payload.

Supported Protocols:

Layer 3: IP, ARP

Layer 4: TCP, UDP, ICMP, IGMP

----------------------------------
**A Brief Note on implementation:**

The program makes use of builtin function getopt to parse the optional command line arguments given as input by the user.

The arguments are stored and validated using the return values provided by calls to pcap library. This allows the program to invalidate any 
objectionable user input.

If the user does not specify any interface, the program opens a session on the default device using pcap_lookupdev. After a couple of checks for the interface to be valid and known to be supported Ethernet headers, the program starts capturing packets indefinitely
until interrupted and registers a callback to packet_handler module for every packet received.

The packet handler dissects the packet for its type and uses header offsets defined in lib/defs.h to typecast the IP/ARP packets to be processed further.

For each of the IP packet types (TCP / UDP / ICMP / IGMP), the position of corresponsing protocol header is determined and then the packet is in turn typecasted into its appropriate struct model.

*Note:* The program makes use of <netinet/icmp.h> header to parse icmp dump. User must have netinet library installed on the host program.

The Program after printing some primitive packet information about source and destination handles control to the payload printing modules, which check if
the user has additionally specified -s option to search payload string, and prints the packet information if found. Thanks to tcpdump.org for raw payload formatting snippet!

----------------------------
**Sample Program Output:**

bagl ❯❯❯ ./sniffer
```
Sniffing on device: en0 
2017-10-10 17:46:17.347462 [Address Masked] > b8:af:67:63:a3:28 type 0x800 len 64 [IP Masked]:51476 > 172.20.226.141:443 TCP 

2017-10-10 17:46:17.642157 [Address Masked] > b8:af:67:63:a3:28 type 0x800 len 64 [IP Masked]:51479 > 17.248.187.16:443 TCP 

2017-10-10 17:46:17.648809 b8:af:67:63:a3:28 > [Address Masked] type 0x800 len 60 17.248.187.16:443 > [IP Masked]:51479 TCP 

2017-10-10 17:46:17.648892 [Address Masked] > b8:af:67:63:a3:28 type 0x800 len 52 [IP Masked]:51479 > 17.248.187.16:443 TCP 

2017-10-10 17:46:17.649408 [Address Masked] > b8:af:67:63:a3:28 type 0x800 len 569 [IP Masked]:51479 > 17.248.187.16:443 TCP 
00000   16 03 01 02 00 01 00 01  fc 03 03 82 fa 51 d9 e9    .............Q..
00016   da e7 b0 c4 0c 67 2a a9  0d 52 68 fe 7c 0d c7 78    .....g*..Rh.|..x
00032   4d 1b fb 0b d6 2c b1 43  b2 fe a9 20 56 d7 0f 5e    M....,.C... V..^
00048   04 b8 7e a3 22 4a 40 9c  4f 5c 01 ce 94 b3 ec 5a    ..~."J@.O\.....Z
00064   86 90 4b c0 19 1b 93 5d  41 55 37 89 00 28 c0 2c    ..K....]AU7..(.,
00080   c0 2b c0 24 c0 23 c0 0a  c0 09 cc a9 c0 30 c0 2f    .+.$.#.......0./
00096   c0 28 c0 27 c0 14 c0 13  cc a8 00 9d 00 9c 00 3d    .(.'...........=
00112   00 3c 00 35 00 2f 01 00  01 8b ff 01 00 01 00 00    .<.5./..........
00128   00 00 17 00 15 00 00 12  67 61 74 65 77 61 79 2e    ........gateway.
00144   69 63 6c 6f 75 64 2e 63  6f 6d 00 17 00 00 00 0d    icloud.com......
00160   00 14 00 12 04 03 08 04  04 01 05 03 08 05 05 01    ................
00176   08 06 06 01 02 01 00 05  00 05 01 00 00 00 00 33    ...............3
00192   74 00 00 00 12 00 00 00  10 00 30 00 2e 02 68 32    t.........0...h2
00208   05 68 32 2d 31 36 05 68  32 2d 31 35 05 68 32 2d    .h2-16.h2-15.h2-
00224   31 34 08 73 70 64 79 2f  33 2e 31 06 73 70 64 79    14.spdy/3.1.spdy
00240   2f 33 08 68 74 74 70 2f  31 2e 31 00 0b 00 02 01    /3.http/1.1.....
00256   00 00 0a 00 08 00 06 00  1d 00 17 00 18 00 15 00    ................
00272   f4 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00288   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00304   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00320   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00336   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00352   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00368   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00384   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00400   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00416   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00432   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00448   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00464   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00480   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00496   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00    ................
00512   00 00 00 00 00                                      .....

2017-10-10 17:46:17.655070 b8:af:67:63:a3:28 > [Address Masked] type 0x800 len 52 17.248.187.16:443 > [IP Masked]:51479 TCP 

2017-10-10 17:46:17.655075 b8:af:67:63:a3:28 > [Address Masked] type 0x800 len 194 17.248.187.16:443 > [IP Masked]:51479 TCP 
00000   16 03 03 00 5e 02 00 00  5a 03 03 6f 22 64 e8 56    ....^...Z..o"d.V
00016   91 49 d0 81 fa a0 09 93  13 66 25 69 0d 5f a4 35    .I.......f%i._.5
00032   1b ce 22 31 05 09 61 43  1c 01 af 20 56 d7 0f 5e    .."1..aC... V..^
00048   04 b8 7e a3 22 4a 40 9c  4f 5c 01 ce 94 b3 ec 5a    ..~."J@.O\.....Z
00064   86 90 4b c0 19 1b 93 5d  41 55 37 89 cc a8 00 00    ..K....]AU7.....
00080   12 ff 01 00 01 00 00 05  00 00 00 10 00 05 00 03    ................
00096   02 68 32 14 03 03 00 01  01 16 03 03 00 20 fe 77    .h2.......... .w
00112   cd d6 19 c5 6e 4e d2 1e  08 d2 b1 a9 15 ce 79 e7    ....nN........y.
00128   49 2d aa f4 e3 c7 1c b6  d4 31 ec 66 38 a7          I-.......1.f8.
```
bagl ❯❯❯ ./sniffer -s google
```
2017-10-10 17:59:43.151581 [Address Masked] > b8:af:67:63:a3:28 type 0x800 len 54 [IP Masked]:59507 > 130.245.255.4:53 UDP
00000   59 e3 01 00 00 01 00 00  00 00 00 00 02 31 33 0e    Y............13.
00016   63 6c 69 65 6e 74 2d 63  68 61 6e 6e 65 6c 06 67    client-channel.g
00032   6f 6f 67 6c 65 03 63 6f  6d 00 00 01 00 01          oogle.com.....

2017-10-10 17:59:43.177442 b8:af:67:63:a3:28 > [Address Masked] type 0x800 len 70 130.245.255.4:53 > [IP Masked]:59507 UDP
00000   59 e3 81 80 00 01 00 01  00 00 00 00 02 31 33 0e    Y............13.
00016   63 6c 69 65 6e 74 2d 63  68 61 6e 6e 65 6c 06 67    client-channel.g
00032   6f 6f 67 6c 65 03 63 6f  6d 00 00 01 00 01 c0 0c    oogle.com.......
00048   00 01 00 01 00 00 01 2c  00 04 d1 55 e8 bd          .......,...U..

2017-10-10 17:59:43.201263 [Address Masked] > b8:af:67:63:a3:28 type 0x800 len 299 [IP Masked]:51619 > 209.85.232.189:443 TCP
00000   16 03 01 00 f2 01 00 00  ee 03 03 43 6f 4e 05 81    ...........CoN..
00016   3a 8e f2 de 75 f1 3d fc  41 6d 04 92 d6 f9 11 be    :...u.=.Am......
00032   c0 c1 29 af 06 aa b2 94  ab 64 d9 00 00 28 c0 2c    ..)......d...(.,
00048   c0 2b c0 24 c0 23 c0 0a  c0 09 cc a9 c0 30 c0 2f    .+.$.#.......0./
00064   c0 28 c0 27 c0 14 c0 13  cc a8 00 9d 00 9c 00 3d    .(.'...........=
00080   00 3c 00 35 00 2f 01 00  00 9d ff 01 00 01 00 00    .<.5./..........
00096   00 00 21 00 1f 00 00 1c  31 33 2e 63 6c 69 65 6e    ..!.....13.clien
00112   74 2d 63 68 61 6e 6e 65  6c 2e 67 6f 6f 67 6c 65    t-channel.google
00128   2e 63 6f 6d 00 17 00 00  00 0d 00 14 00 12 04 03    .com............
00144   08 04 04 01 05 03 08 05  05 01 08 06 06 01 02 01    ................
00160   00 05 00 05 01 00 00 00  00 33 74 00 00 00 12 00    .........3t.....
00176   00 00 10 00 30 00 2e 02  68 32 05 68 32 2d 31 36    ....0...h2.h2-16
00192   05 68 32 2d 31 35 05 68  32 2d 31 34 08 73 70 64    .h2-15.h2-14.spd
00208   79 2f 33 2e 31 06 73 70  64 79 2f 33 08 68 74 74    y/3.1.spdy/3.htt
00224   70 2f 31 2e 31 00 0b 00  02 01 00 00 0a 00 08 00    p/1.1...........
00240   06 00 1d 00 17 00 18                                .......
```
bagl ❯❯❯ ./sniffer "dst google.com && icmp"                                                                                                                                               
```
Sniffing on device: en0
2017-10-10 18:02:04.239115 IP [IP Masked] > 172.217.6.206: ICMP echo request ,id 7013, seq 0
00000   59 dd 43 5c 00 03 a5 da  08 09 0a 0b 0c 0d 0e 0f    Y.C\............
00016   10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f    ................
00032   20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f     !"#$%&'()*+,-./
00048   30 31 32 33 34 35 36 37                             01234567

2017-10-10 18:02:05.243102 IP [IP Masked] > 172.217.6.206: ICMP echo request ,id 7013, seq 1
00000   59 dd 43 5d 00 03 b5 41  08 09 0a 0b 0c 0d 0e 0f    Y.C]...A........
00016   10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f    ................
00032   20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f     !"#$%&'()*+,-./
00048   30 31 32 33 34 35 36 37                             01234567

2017-10-10 18:02:06.243557 IP [IP Masked] > 172.217.6.206: ICMP echo request ,id 7013, seq 2
00000   59 dd 43 5e 00 03 b7 0d  08 09 0a 0b 0c 0d 0e 0f    Y.C^............
00016   10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f    ................
00032   20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f     !"#$%&'()*+,-./
00048   30 31 32 33 34 35 36 37                             01234567
```
