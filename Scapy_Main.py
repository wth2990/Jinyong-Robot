from scapy.all import *
import sys

#pkt = sniff(filter='host 210.242.243.179',prn=lambda x:x.summary())

#a=Ether()/IP(dst="210.242.243.179")/TCP()


class operation(object):
    def __init__(self, d):
        self._dict = d

    @staticmethod
    def print(data_string):
        new_string = "";
        for char_index in range(len(data_string)):
            if char_index % 2 == 1 :
                new_string = new_string + data_string[char_index] + ' ';
            else:
                new_string = new_string + data_string[char_index];
        print(new_string.upper())
    '''
    @staticmethod
    def xor_strings(ba1, ba2):
        from itertools import cycle
        return bytes([_b ^ _a for _b, _a in zip(ba2, cycle(ba1))])
    '''
    @staticmethod
    def xor_strings(ys):
        Str_Ret = ""
        #print("lens:"+str(len(ys)))
        for i in range(0,len(ys)):
            if i % 2 == 0:
                char1 = 0x0 ^ int(ys[i], 16);
                char2 = 0xd ^ int(ys[i+1], 16);
                Str_Ret = Str_Ret + f'{char1:x}' + f'{char2:x}';
        #print("Str_Ret")
        return Str_Ret;

packet_count = 0
packets = {}
accepted = {}
YOUR_IP = '10.0.0.1'
FILTER = "host 210.242.243.179"

def handshake_status(packet):
    global packets,accepted,packet_count

    flag = packet[0][1].sprintf('%TCP.flags%')
    data = bytes(packet[0][1].payload)
    print(packet.__dict__)
    #import numpy
    #n_data = numpy.fromstring(data, dtype='uint8')
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst

    hex_a = data.hex()
    #print(hex_a)
    import binascii;
    binary_a = binascii.unhexlify(hex_a)

    data_xor = operation.xor_strings(hex_a);
    if flag == 'P':
        print("P");
    elif flag == 'PA':
        print("--- PA ---");
        data_string = data.hex();
        operation.print(data_string);
        print("--- Xor ---")
        data_string2 = data_xor;
        operation.print(data_string2);
    elif flag == 'A':
        Nonething = ""
    else:
        print("--- flag: " + flag)
        data_string = data.hex();
        operation.print(data_string);


if __name__ == '__main__':
    sniff(filter=FILTER ,prn=handshake_status)
