'''
==================================================================================================
												||
	Copyright (C) 2021 IoT Research & Innovation Lab (IRIL), KICS, UET Lahore, Pakistan	|| 
												||
	Paper Title : A Framework for Malicious Traffic Detection in IoT Healthcare		||
												||
	Authors : Faisal Hussain, Syed Ghazanfar Abbas, Ghalib A.Shah, Ivan Miguel Pires, 	||
		  Farrukh Shahzad, Ubaid U. Fayyaz, Nuno M. Garcia, Eftim Zdravevski		||
												||
	Code Description : Dataset Generator: A python utility to extract features from a  	||
			   given .pcap file and save it into csv.				||
												||
	Date created : 19/04/2021								||
												||
	Python Version : 3.6 or obove								||
												||
	Libraries Required : tshark (install in ubuntu using: sudo apt-get install tshark)	||
												||
	License : General Public License (GNU)							||
												||
	Correspondance : faisal.hussain.engr@gmail.com & ghazanfar.abbas@kics.edu.pk 		||
												||
	How to Run : (i)  Give path of input pcap File						||
		     (ii) Run one of the following commands:					||
			  >> python3 pcap2Csv.py 						||
			  >> sudo python3 pcap2Csv.py						||
												||
==================================================================================================
'''

import os

inputFilePath = "/home/iot/Desktop/ICU_Usecase/Pcaps/mqtt2.pcap" #mention path+Name of the pcap file

outputFilePath = inputFilePath+'_.csv'

frame_Features = "-e frame.time_delta -e frame.time_relative -e frame.len "
flow_Features = "-e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e ip.proto -e ip.ttl "
tcp_Features = "-e tcp.flags -e tcp.time_delta -e tcp.len -e tcp.ack -e tcp.connection.fin -e tcp.connection.rst -e tcp.connection.sack -e tcp.connection.syn -e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.push -e tcp.flags.reset -e tcp.flags.syn -e tcp.flags.urg -e tcp.hdr_len -e tcp.payload -e tcp.pdu.size -e tcp.window_size_value -e tcp.checksum "

mqtt_Features = "-e  mqtt.clientid -e mqtt.clientid_len -e mqtt.conack.flags -e mqtt.conack.val -e mqtt.conflag.passwd -e mqtt.conflag.qos -e mqtt.conflag.reserved -e mqtt.conflag.retain -e  mqtt.conflag.willflag -e mqtt.conflags -e mqtt.dupflag -e mqtt.hdrflags -e mqtt.kalive -e mqtt.len -e mqtt.msg -e mqtt.msgtype -e mqtt.qos -e mqtt.retain -e mqtt.topic -e mqtt.topic_len -e mqtt.ver -e mqtt.willmsg_len "

others = "-E header=y -E separator=, -E quote=d -E occurrence=f "



allFeatures = frame_Features + flow_Features + tcp_Features + mqtt_Features + others

command = 'tshark -r '+ inputFilePath + ' -T fields ' + allFeatures + '> '+ outputFilePath



#print(command)

print(f"--- Input File: {inputFilePath} ---")

print('--Processing File--')

print("=== Extracting Features and Generating CSV===")

os.system(command)

print("--- Done ---")
