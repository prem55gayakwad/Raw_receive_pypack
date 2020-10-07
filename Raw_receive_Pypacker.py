import sys, os
import binascii
import platform
import time, datetime
import threading, queue
import binascii

from broadway2 import Broadway, broadway_api, RawReceiver, RawRxHeaderTypes, EthRawFrame

from pypacker.layer567 import ptpv2
from pypacker.layer3 import ip, icmp
from pypacker.layer12 import ethernet, arp

DefaultInst = 0 # Use first found USB-Adapter
DefaultPayload = 1480

def main(args):

    inst = DefaultInst
    payload = DefaultPayload

     # create adapter singleton
    base = Broadway()

    print('Connected Devices: ')
    print('='*25)
  
    aList = base.get_raw_adapters()

    if len(aList) < 1:
        print('no Raw-Adapter found')
        sys.exit(-1)

    inst = 0

    rawAdapter = base.get_adapter(aList[inst][0])
    # get adapter selected by instance


    if rawAdapter != None:
        devRx = base.open_raw_rx(rawAdapter.Inst, RawRxHeaderTypes.HeaderType2)
        print('Raw Rx Device opened: {0}'.format(aList[inst][1]))
        
        rawReceiver = RawReceiver(devRx)

        rawReceiver.enable()

        print('Receiver running... Ctrl-C to exit')


        #send........................
        cnt = 1
        for a in aList:
            print('[ {0:2} ]: {1} / {2}'.format(cnt, a[1], a[0]))
            cnt += 1
        try:
            sel = int(input('Enter Number to use:'))
        except:
            sel = 0
    else:
        sel = 0

    inst, friendlyName = aList[sel-1]

    adapter = base.get_adapter(inst)

    macSrc = adapter.MACAddress

    print('Open Adapter to send raw: {0} / {1}'.format(friendlyName, inst))    
    print('='*30)
    if sel >= 0:
        devTx = base.open_raw_tx(inst)
        print('Raw Sender opened: {0}'.format(friendlyName))
        
        if devTx == None:
            sys.exit(-1)

        payloadData = ''
        for j in range(0, payload):
            payloadData += '{0:02X}'.format(j & 0xFF)

        frameId = 0  # only first seq=0 has no timestamp, all following will use hw timestamp from previous send result
        hwTimeStamp = (0,0)
        print('Sending data {0}.... Press <Ctrl-C> to stop/exit'.format(payload))
#.....................................
        try:
            while 1:
                # read_block with max. 500 frames and timeout after 500 ms
                result = rawReceiver.read_block(500, 500)
                # returns array of tuples (timestamp, seqCounter, Ethernet-Frame)

                # walk through all stored buffer data
                for res in result:
                    ethRaw = EthRawFrame(res)
                                        
                    print('Received: {0}'.format(ethRaw.SequenceCnt))
                                
                    eth = ethernet.Ethernet(ethRaw.EthFullFrame)
                    print('decode Eth: src:{0} dst: {1}'.format(eth.src_s, eth.dst_s))

                    print('Decoder: {0}'.format(eth))

                    arpProto = eth[arp.ARP]
                    if arpProto != None:
                        print('ARP: {0}'.format(arpProto.sha_s))
                    # verify to receive real IP-Protocols
                    # TODO: Send IP_Frames from link-partner (FC602 or S32K148)
                    ipvx = eth[ip.IP]
                    if ipvx != None:
                        print('IP-Traffic!')
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                # no VLAN, use LLC default protocol for correct decoding in wireshark
                sendData = 'FFFFFFFFFFFF' + macSrc + '{0:04X}'.format(payload+18) + '1234' + '{0:08X}'.format(frameId) + '{0:016X}'.format(hwTimeStamp[0]) + '{0:08X}'.format(hwTimeStamp[1]) + payloadData
                
                # Single-VLAN on VLAN=0x01 using LLC protocol
                #sendData = 'FFFFFFFFFFFFFC0011223344' + '81000001' + '{0:04X}'.format(payload+18) + '1234' + '{0:08X}'.format(frameId) + '{0:016X}'.format(hwTimeStamp[0]) + '{0:08X}'.format(hwTimeStamp[1]) + payloadData
                
                # Double-Tagged VLAN on VLAN-Outer=0x07 and VLAN-Inner=0x15 using LLC protocol
                #sendData = 'FFFFFFFFFFFFFC0011223344' + '88A8000781000015' + '{0:04X}'.format(len(payloadData)+32) + '{0:08X}'.format(frameId) + '{0:016X}'.format(hwTimeStamp[0]) + '{0:08X}'.format(hwTimeStamp[1]) + payloadData
                binData = binascii.a2b_hex(sendData)

                res = broadway_api.wait_for_tx(devTx, 1000)
                if not res:
                    print('waitfor tx failed!')

                frameId = broadway_api.submit_raw_frame(devTx, binData)

                res = broadway_api.send_raw_frames(devTx)
            
                res = broadway_api.wait_for_raw_tx_completion(devTx, frameId, 1000)

                hwTimeStamp = broadway_api.get_raw_tx_timestamp(devTx, frameId)

                time.sleep(0.5)
        except KeyboardInterrupt:
               base.close(devTx)
            

if __name__ == "__main__":
    main(sys.argv)
         
