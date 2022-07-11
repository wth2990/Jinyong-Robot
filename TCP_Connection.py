
from scapy.all import *;
from Scapy_Main import *;
src = "152.77.153.188"#sys.argv[1]
dst = "210.242.243.179"#sys.argv[2]
sport = 59474
dport = 6732#int(sys.argv[3])
FILTER = "host 210.242.243.179"
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
        operation.print(data_string,sr_flag,None);
    elif flag == 'PA':
        print("--- PA ---");
        data_string = data.hex();
        operation.print(data_string,sr_flag,None);
        #print("--- Xor ---")
        '''
        data = operation.locate_data(data_string,sr_flag)
        key = operation.get_change_key(data);
        decoded_data = operation.xor_strings(key,data);
        operation.cut_head(decoded_data,sr_flag);
        '''
    elif flag == 'A':
        Nonething = ""
    else:
        print("--- flag: " + flag)
        data_string = data.hex();
        operation.print(data_string,sr_flag,None);

def scapy_function():
    sniff(filter=FILTER ,prn=handshake_status)

x = threading.Thread(target=scapy_function)
x.start()

s = TCP_client.tcplink(Raw, dst, dport)
hex_string = "6BDB8B9E438E939FDF44969FA8CBD2AECBD1C8AB";
#hex_string = "ABDB8B9E438E939FDF44969FA8CBD2AECBD1C8AB"
bt = bytearray.fromhex(hex_string)
s.send(bt)
s.recv()
hex_string = "EF5F5A6F192FCA201B4CFA021BA86C0E1B3D77381B11D1181B4F4C191BDEED1A1B2F781B1B2B28131BCB741B1BBC641B1B6A811A1B0A62181B8C4A3B1B2685101B"
hex_string = "269693A6D0E603E9D28533CBD261A5C7D2F4BEF1D2D818D1D28685D0D21724D3D2E6B1D2D2E2E1DAD202BDD2D275ADD2D2A348D3D2C3ABD1D24583F2D2EF4CD9D2"
bt = bytearray.fromhex(hex_string)
s.send(bt)
s.recv()
