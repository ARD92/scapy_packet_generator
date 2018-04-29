#Generate traffic using Scapy python module

#Install scapy
```
pip install scapy
``` 


```
#Edit input_json file according to needs

If packet has to be generated based on raw/hex input
flow = NONE
trans = NONE
raw_hex_load = raw_<raw string >
			   hex_<hex_string>

If plain ICMP packets: 
trans = ICMP
flow = 1

If plain TCP/UDP packets to create multiple flows
trans =TCP/UDP
flows >=1

flows are created based on incremental dest ports   
```

#Usage
```
root@compute17:~# python scapy_traffic_test.py --help
usage: scapy_traffic_test.py [-h] [--WP] [--T TIME]

optional arguments:
  -h, --help            show this help message and exit
  --w, -wrpcap        write to pcap file
  --t TIME, -time TIME
                        time duration for which traffic should pass
```
