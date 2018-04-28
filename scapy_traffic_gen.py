'''
Author: Aravind Srinivas S.P

To Do:
2. read pcap file and dump info as a json format
3. exit traffic gen app unpon ENTER key encounter (useful when someone runs with time 10000s and want to close half way)
4. find multiplier for generation of rate (currently 100000 loop gives ~33Mbps)
'''

import os
import argparse
import subprocess
import json
import binascii

########################################
# check if scapy module is installed
########################################

app = subprocess.call(['which', 'scapy'])
if app != 0:
	print "scapy not found, installing scapy"
	subprocess.Popen(['sudo pip install scapy'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

from scapy.all import *
from scapy.utils import rdpcap
from scapy.utils import wrpcap

parser = argparse.ArgumentParser()
#parser.add_option('--RP', '-rdpcap', action='store', dest='read_pcap', help="read pcap file", default="False")
parser.add_argument('--w','-wrpcap', action='store_true',dest='write_pcap',default="False", help='write to pcap file')
parser.add_argument('--t', '-time', action='store', dest='time', help ='time duration for which traffic should pass', default = 1)
args = parser.parse_args()


##############################################
# packet class to create, write, read and send
##############################################

class packet:

	def __init__(self,trans,flow):
		self.trans = str(trans)
		self.flow = str(flow)
		#print(self.trans)
		#print(self.flow)

		if ((self.trans != 'NONE') and (self.flow != 'NONE')):
			self.flow = int(self.flow)

			if ((self.trans == 'ICMP') and (self.flow != 1)):
				print("wrong value received, if you want multiple flows,please use TCP/UDP and if you want to use ICMP please use flow:1 in json")
				exit()

			elif self.trans == 'ICMP':
				self.pkt = Ether()/IP()/ICMP()/Raw()

			elif self.trans == 'TCP':
				self.pkt = Ether()/IP()/TCP()/Raw()

			elif self.trans =='UDP':
				self.pkt = Ether()/IP()/UDP()/Raw()

	def create(self,src_mac,dst_mac,src_ip,dst_ip,payload):
		'''
		write the packet created into a pcap
		To do: vary the payload, give that as an optional argument
		'''

		if (self.trans != 'ICMP'):
			for i in range(2000,2000+self.flow):
				self.pkt[Ether].src = src_mac
				self.pkt[Ether].dst = dst_mac
				self.pkt[IP].src = src_ip
				self.pkt[IP].dst = dst_ip

				if self.trans == 'TCP':
					#self.pkt[TCP].sport = i
					self.pkt[TCP].dport = i
				if self.trans == 'UDP':
					#self.pkt[UDP].sport = i
					self.pkt[UDP].dport = i

				self.pkt[Raw].load = payload
				#self.pkt.summary()
				#self.pkt.show()

				''' the below is commented to choose tcpreplay or scapy to send packets'''
				wrpcap("traffic_{}_{}.pcap".format(self.trans,self.flow),self.pkt,append=True)
			return ("traffic_{}_{}.pcap".format(self.trans, self.flow))

		elif ((self.trans == 'ICMP') and (self.flow == 1)):
			self.pkt[Ether].src = src_mac
			self.pkt[Ether].dst = dst_mac
			self.pkt[IP].src = src_ip
			self.pkt[IP].dst = dst_ip
			self.pkt[Raw].load = payload
			wrpcap("traffic_{}_{}.pcap".format(self.trans, self.flow), self.pkt, append=True)
			return ("traffic_{}_{}.pcap".format(self.trans, self.flow))

		else:
			print ("wrong value received, if you want multiple flows, please use TCP/UDP and if you want to use ICMP please use flow:1 in json")
			exit()

	def rawhexsend(self,data,loop,iface,time):
		"""
		send raw hex data
		"""
		self.type = data[:3]

		if self.type=="raw":
			self.pkt = Ether(data[4:])

			for i in range(0,int(time)):
				sendpfast(self.pkt, loop=int(loop), iface=iface)
				i+1

		if self.type=="hex":
			self.payload = binascii.unhexlify(data[4:])
			self.pkt = Ether(self.payload)

			for i in range(0,int(time)):
				sendpfast(self.pkt, loop=int(loop), iface=iface)
				i+1
		
		return self.pkt
					
	#def read_pcap(self,file_name):
		"""
		To Do
		read pcap and dump information/modify packet and recreate pcap
		"""

	def send(self,pkt,loop,iface,time):
		"""
		 send packets using scapy by reading pcap
		"""
		self.read_packet = rdpcap(pkt)

		for i in range(0,int(time)):
			sendpfast(self.read_packet,loop=int(loop),iface=iface)
			i = i +1

def usage():
	print 25*"#"
	print ("Default 1s timer: python scapy_traffic_gen.py\n")
	print ("To write to Pcap and send for 10s: python scapy_traffic_gen.py --w --t 10\n")
	print 25*"#"
	
def Main():
	data = json.load(open('input_json.json'))
	
	if ((data['trns']=='NONE') and (data['flow']=='NONE')):

		if data['raw_hex_load']:
			"""
			Need mention both trns and flow as 'NONE' in the json file
			"""
			pkt = packet(data['trns'],data['flow'])
			traf = pkt.rawhexsend(data['raw_hex_load'], data['loop'], data['intf'], args.time)
			
			if not args.write_pcap == 'False':			
				wrpcap("traffic_{}.pcap".format(data['raw_hex_load'][:3]), traf, append=True)

		else:
			print("enter hex data under key:raw_hex_load in the json file")

	else:
		pkt = packet(data['trns'],data['flow'])
		traf = pkt.create(data['srcmac'],data['dstmac'],data['srcip'],data['dstip'], data['payload'])
		pkt.send(traf, data['loop'], data['intf'], args.time)

		#################################################
		# delete pcap file if write pcap option not chosen
		##################################################

		if args.write_pcap == 'False':
			os.system('rm {}'.format(traf))

if __name__ == '__main__':
	try:
		usage()
		Main()
	except:
		usage()
