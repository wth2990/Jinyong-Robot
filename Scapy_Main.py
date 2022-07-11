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
                
        if sr_flag == "S":
            print("==> " + new_string.upper())
        elif sr_flag == "R":
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
                        operation.print(input[pos[i]+4:pos[i+1]],sr_flag)
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
src:152.77.153.188
dst:210.242.243.179
src:210.242.243.179
dst:152.77.153.188
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
    if src_ip == "152.77.153.188":
        sr_flag = "S";#Send;
        print("Dest Port: " + str(tcp_dport))
        #print("Send!");
    elif src_ip == "210.242.243.179":
        sr_flag = "R";
        #print("Received!");
    else:
        sr_flag = "N";
    hex_a = data.hex()
    #print(hex_a)
    import binascii;
    binary_a = binascii.unhexlify(hex_a)

    if flag == 'P':
        print("P");
    elif flag == 'PA':
        print("--- PA ---");
        data_string = data.hex();
        #print("--- Xor ---")
        data = operation.locate_data(data_string,sr_flag)
        key = operation.get_change_key(data);
        decoded_data = operation.xor_strings(key,data);
        operation.cut_head(decoded_data,sr_flag);
    elif flag == 'A':
        Nonething = ""
    else:
        print("--- flag: " + flag)
        data_string = data.hex();
        operation.print(data_string,sr_flag);


def scapy_function():
    sniff(filter=FILTER ,prn=handshake_status)

def pop_data():
    while 1:
        if len(operation.data[0]) > 0 and len(operation.data[1]) > 0:
            the_str = operation.data[0].pop(0);
            the_flag = operation.data[1].pop(0);
            #print(type(the_str))# + " -- " + type(the_flag)
            if not isinstance(the_str, int):
                operation.print(the_str,the_flag);

def the_send():
    # VARIABLES
    src = "152.77.153.188"#sys.argv[1]
    dst = "210.242.243.179"#sys.argv[2]
    sport = 59474
    dport = 6732#int(sys.argv[3])

    # SYN
    ip=IP(src=src,dst=dst)
    SYN=TCP(sport=sport,dport=dport,flags='S',seq=1000)
    SYNACK=sr1(ip/SYN)

    # ACK
    ACK=TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
    send(ip/ACK)

if __name__ == '__main__':
    import threading
    _ui = UI();
    x = threading.Thread(target=scapy_function)
    x.start()
    the_send();
    '''
    y = threading.Thread(target=pop_data)
    y.start()'''
    _ui.start();
