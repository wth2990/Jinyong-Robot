from scapy.all import *
import sys
from datetime import datetime
from UI import UI;
#pkt = sniff(filter='host 210.242.243.179',prn=lambda x:x.summary())

#a=Ether()/IP(dst="210.242.243.179")/TCP()

'''
1, Find 0000 in the payload string
2. Get the data string, which starts after 0000
3.
'''
class operation(object):
    #data = [2][];

    data = [[0 for x in range(2)] for y in range(100000)]

    def __init__(self, _mdt):
        #operation.Main_Display_Text = _mdt;
        print("");

    @staticmethod
    def print(data_string,sr_flag,display):
        dt = datetime.now();
        ts = datetime.timestamp(dt)

        date_time = datetime.fromtimestamp(ts);
        # convert timestamp to string in dd-mm-yyyy HH:MM:SS
        str_date_time = date_time.strftime("%d-%m-%Y, %H:%M:%S");

        new_string = str_date_time + ":   ";
        for char_index in range(len(data_string)):
            if char_index % 2 == 1 :
                new_string = new_string + data_string[char_index] + ' ';
            else:
                new_string = new_string + data_string[char_index];
                
        if sr_flag == "S":      #send
            print("==> " + new_string.upper())
        elif sr_flag == "R":    #receive
            print("<== " + new_string.upper())

        if new_string != "" and display != None:
            display.see("end")
            #print(str(line_no_int));
            UI.maintain();
            if sr_flag == "S":
                display.insert("end", new_string.upper() + '\n',"warning")
                with open('send.txt', 'a') as fda:
                    fda.write(f'\n{new_string.upper()}')
            elif sr_flag == "R":
                display.insert("end", new_string.upper() + '\n')
                with open('receive.txt', 'a') as fdb:
                    fdb.write(f'\n{new_string.upper()}')
            else:
                display.insert("end", new_string.upper() + '\n')

    #xor with 0x0d
    @staticmethod
    def xor_strings(key,ys):
        Str_Ret = ""
        #print("lens:"+str(len(ys)))
        for i in range(0,len(ys)):
            if i % 2 == 0:
                try:
                    #print('i:' + str(i) + " len:" + str(len(ys)));
                    char1 = int(key[0], 16) ^ int(ys[i], 16);
                    char2 = int(key[1], 16) ^ int(ys[i+1], 16);
                    Str_Ret = Str_Ret + f'{char1:x}' + f'{char2:x}';
                except:
                    Str_Ret = Str_Ret;
                    print("Error in XOR!");
        #print("Str_Ret")
        return Str_Ret;

    @staticmethod
    def cut_head(input,sr_flag):
        num = 0;
        pos = [];
        for i in range(0,len(input)):
            if input[i:i+4].upper() == "F444":
                pos.append(i);
                #print("---" + str(pos[num]))
                num = num + 1;
        #print("--- No. of Pos: " + str(len(pos)))
        if len(pos) > 0:
            for i in range(0,len(pos)):
                if i < len(pos) - 1:
                    the_str = operation.filter_message(input[pos[i]:pos[i+1]],sr_flag);
                    if the_str != None:
                        #print(the_str)
                        operation.data[0].append(str(the_str))
                        operation.data[1].append(str(sr_flag))
                else:
                    the_str = operation.filter_message(input[pos[i]:],sr_flag)
                    if the_str != None:
                        #print(the_str)
                        operation.data[0].append(str(the_str))
                        operation.data[1].append(str(sr_flag))
    @staticmethod
    def locate_data(input,sr_flag):
        num = 0;
        pos = [];
        for i in range(0,len(input)):
            if input[i:i+4].upper() == "0000":
                pos.append(i);
                #print("---" + str(pos[num]))
                num = num + 1;
        #print("--- No. of Pos: " + str(len(pos)))
        if len(pos) > 0:
            for i in range(0,len(pos)):
                if i < len(pos) - 1:
                    if input[pos[i]+4:pos[i+1]] != "" and input[pos[i]+4:pos[i+1]] != None:
                        operation.print(input[pos[i]+4:pos[i+1]],sr_flag,None)
                else:
                    return input[pos[i]+4:]

    @staticmethod
    def get_change_key(ys):
        Str_Ret = ""
        #print("lens:"+str(len(ys)))
        for i in range(0,2):
            if i % 2 == 0:
                char1 = 0xf ^ int(ys[i], 16);
                char2 = 0x4 ^ int(ys[i+1], 16);
                Str_Ret = Str_Ret + f'{char1:x}' + f'{char2:x}';
        #print("Decode Key:" + Str_Ret)
        return Str_Ret;

    @staticmethod
    def filter_message(input,sr_flag):
        #print("filter: " + input);


        #filter the message with 0D8A03
        if len(input) > 10:
            if input[4:10].upper() == "0D8A03":
                return None;
            elif input[4:8].upper() == "8CBD":
                return None;
            elif input[6:8].upper() == "32":
                return None;
            elif input [6:8].upper() == "A6":
                #return None;
                the_str = input[8:];
                result = bytearray.fromhex(the_str).decode('big5');
                with open('decode.txt', 'a') as fd:
                    fd.write(f'\n{result}');
                UI.Second_Display_Text.insert("end", result + '\n')
                return None;
            elif input[6:8].upper() == "60":#60會顯示用戶名
                '''
                try:
                    the_str = input[16:];
                    result = bytearray.fromhex(the_str).decode('big5');
                    UI.Second_Display_Text.insert("end", result + '\n')
                except:
                    print("decode error!!!")
                '''
                return None;
            elif input[6:10].upper() == "1406":#名門的公告
                #return None;
                the_str = input[10:];
                result = bytearray.fromhex(the_str).decode('big5');
                with open('decode.txt', 'a') as fd:
                    fd.write(f'\n{result}');
                UI.Second_Display_Text.insert("end", result + '\n')
                return None;
        return input;
packet_count = 0
packets = {}
accepted = {}
#YOUR_IP = '10.0.0.1'
FILTER = "host 210.242.243.179"
'''
src:172.20.10.6
dst:210.242.243.179
src:210.242.243.179
dst:172.20.10.6
'''
def handshake_status(packet):
    global packets,accepted,packet_count

    flag = packet[0][1].sprintf('%TCP.flags%')
    data = bytes(packet[0][1].payload)

    #print(packet.__dict__)
    #import numpy
    #n_data = numpy.fromstring(data, dtype='uint8')
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    tcp_dport=packet[0][1].dport#6732
    #print("A - from IP: " + src_ip);
    if src_ip == "172.20.10.6":
        sr_flag = "S";#Send;
        #print("Dest Port: " + str(tcp_dport))
        #print("==>");
    elif src_ip == "210.242.243.179":
        sr_flag = "R";
        #print("<==");
    else:
        sr_flag = "N";
    hex_a = data.hex()
    #print(hex_a)
    import binascii;
    binary_a = binascii.unhexlify(hex_a)

    if flag == 'P':
        print("--- flag: " + flag)
        data_string = data.hex();
        operation.print(data_string,sr_flag,None);
    elif flag == 'PA':
        print("--- flag: " + flag)
        data_string = data.hex();
        #print("--- Xor ---")
        data = operation.locate_data(data_string,sr_flag)
        key = operation.get_change_key(data);
        decoded_data = operation.xor_strings(key,data);
        operation.cut_head(decoded_data,sr_flag);
        print("Raw:")
        operation.print(data_string,sr_flag,None);
        print("Decoded:")
        operation.print(decoded_data,sr_flag,None);
    elif flag == 'A':
        Nonething = ""
    else:
        print("--- flag: " + flag)
        data_string = data.hex();
        operation.print(data_string,sr_flag,None);


def scapy_function():
    sniff(filter=FILTER ,prn=handshake_status)

def pop_data():
    while 1:
        if len(operation.data[0]) > 0 and len(operation.data[1]) > 0:
            the_str = operation.data[0].pop(0);
            the_flag = operation.data[1].pop(0);
            #print(type(the_str))# + " -- " + type(the_flag)
            if not isinstance(the_str, int):
                operation.print(the_str,the_flag,None);

def the_send():
    # VARIABLES
    src_local = "172.20.10.6"#sys.argv[1]
    dst_local = "210.242.243.179"#sys.argv[2]
    sport = 59474
    dport = 6732#int(sys.argv[3])

    import socket
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #p=IP(dst=dst_local)/TCP(flags="S", sport=sport, dport=dport)
    s.connect((dst_local,dport))
    #s.send(p)'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((dst_local,dport))
        s.sendall(bytes.fromhex('6BDB8B9E9C1A939FFAD8959FA8CBD2AECBD1C8AB'))
        data = s.recv(1024)
        print("Received {data!r}")
        s.sendall(bytes.fromhex('DE6E6B5E281EFB112A7DCB332A995D3F2A0C46092A20E0292A7E7D282AEFDC2B2A1E492A2A1A19222AFA452A2A8D552A2A5BB02B2A3B53292ABD7B0A2A17B4212A'))
        data = s.recv(1024)
        print("Received {data!r}")

        
    

    '''
    # SYN
    ip=IP(src=src_local,dst=dst_local)
    SYN=TCP(sport=sport,dport=dport,flags='S',seq=1000)
    SYNACK=sr1(ip/SYN)

    # ACK
    ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    send(ip/ACK)
    '''
if __name__ == '__main__':
    import threading
    _ui = UI();
    x = threading.Thread(target=scapy_function)
    x.start()
    '''
    y = threading.Thread(target=pop_data)
    y.start()
    '''
    _ui.start();
    #the_send();
'''

==> 31-12-2022, 02:43:29:   C6 11 1A 4C BB 9B 3E 90 F3 88 B6 23 50 18 04 04 78 0A 00 00 98 28 2D 18 6E 58 BD 57 6C 3B 8D 75 6C DF 1B 79 6C 4A 00 4F 6C 66 A6 6F 6C 38 3B 6E 6C A9 9A 6D 6C 58 0F 6C 6C 5C 5F 64 
6C BC 03 6C 6C CB 13 6C 6C 1D F6 6D 6C 7D 15 6F 6C FB 3D 4C 6C 51 F2 67 6C
Decoded:
==> 31-12-2022, 02:43:29:   F4 44 41 74 02 34 D1 3B 00 57 E1 19 00 B3 77 15 00 26 6C 23 00 0A CA 03 00 54 57 02 00 C5 F6 01 00 34 63 00 00 30 33 08 00 D0 6F 00 00 A7 7F 00 00 71 9A 01 00 11 79 03 00 97 51 20 
00 3D 9E 0B 00

Raw:
==> 31-12-2022, 02:46:41:   C6 17 1A 4C A5 FA 0E 73 DA 32 90 4A 50 18 04 04 6F 83 00 00 DE 6E 6B 5E 28 1E FB 11 2A 7D CB 33 2A 99 5D 3F 2A 0C 46 09 2A 20 E0 29 2A 7E 7D 28 2A EF DC 2B 2A 1E 49 2A 2A 1A 19 22 
2A FA 45 2A 2A 8D 55 2A 2A 5B B0 2B 2A 3B 53 29 2A BD 7B 0A 2A 17 B4 21 2A
Decoded:
==> 31-12-2022, 02:46:41:   F4 44 41 74 02 34 D1 3B 00 57 E1 19 00 B3 77 15 00 26 6C 23 00 0A CA 03 00 54 57 02 00 C5 F6 01 00 34 63 00 00 30 33 08 00 D0 6F 00 00 A7 7F 00 00 71 9A 01 00 11 79 03 00 97 51 20 
00 3D 9E 0B 00
''' 