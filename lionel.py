
from scapy.all import sniff, TCP, UDP, IP, ICMP, Ether
import logging

# Configuration du logging pour enregistrer les informations dans un fichier
logging.basicConfig(
    filename='sniffer_log.txt',
    filemode='a',  # 'a' pour ajouter à la fin du fichier
    format='%(asctime)s - %(message)s',
    level=logging.INFO
)

def process_packet(packet):
    log_info = []

    # Vérification de la couche Ethernet
    if packet.haslayer(Ether):
        ether = packet[Ether]
        log_info.append("### Couche Ethernet ###")
        log_info.append(f"  Destination MAC: {ether.dst}")
        log_info.append(f"  Source MAC: {ether.src}")
        log_info.append(f"  Type: {ether.type}")

    # Vérification de la couche IP
    if packet.haslayer(IP):
        ip = packet[IP]
        log_info.append("### Couche IP ###")
        log_info.append(f"  Version: {ip.version}")
        log_info.append(f"  IHL: {ip.ihl}")
        log_info.append(f"  TOS: {ip.tos}")
        log_info.append(f"  Longueur: {ip.len} octets")
        log_info.append(f"  ID: {ip.id}")
        log_info.append(f"  Flags: {ip.flags}")
        log_info.append(f"  TTL: {ip.ttl}")
        log_info.append(f"  Protocole: {ip.proto}")
        log_info.append(f"  IP Source: {ip.src}")
        log_info.append(f"  IP Destination: {ip.dst}")

        # Vérification des couches TCP/UDP/ICMP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            log_info.append("### Couche TCP ###")
            log_info.append(f"  Port Source: {tcp.sport}")
            log_info.append(f"  Port Destination: {tcp.dport}")
            log_info.append(f"  Flags: {tcp.flags}")
            log_info.append(f"  Sequence Number: {tcp.seq}")
            log_info.append(f"  Acknowledgment Number: {tcp.ack}")

            # Extraction du message HTTP si disponible
            if tcp.dport == 80 or tcp.sport == 80:
                try:
                    http_payload = bytes(tcp.payload).decode('utf-8')
                    log_info.append("### Couche Application (HTTP) ###")
                    log_info.append(f"  Message HTTP: {http_payload}")
                except UnicodeDecodeError:
                    log_info.append("  Message HTTP: [Données binaires ou encodage non UTF-8]")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            log_info.append("### Couche UDP ###")
            log_info.append(f"  Port Source: {udp.sport}")
            log_info.append(f"  Port Destination: {udp.dport}")
            log_info.append(f"  Longueur: {udp.len} octets")

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            log_info.append("### Couche ICMP ###")
            log_info.append(f"  Type: {icmp.type}")
            log_info.append(f"  Code: {icmp.code}")
            log_info.append(f"  Checksum: {icmp.chksum}")

        # Taille du paquet
        log_info.append(f"Taille du paquet: {len(packet)} octets")

        # Détails complets du paquet
        log_info.append("### Détails complets du paquet ###")
        log_info.append(packet.show(dump=True))  # Utilisation de dump=True pour obtenir une chaîne

        # Enregistrement des informations dans le fichier log
        logging.info("\n".join(log_info))
        logging.info("-" * 50)  # Séparateur entre les paquets

        # Optionnel : Afficher à l'écran
        print("\n".join(log_info))
        print("-" * 50)

# Démarrage du sniffer
if __name__ == "__main__":
    print("Démarrage du sniffer... Appuyez sur Ctrl+C pour arrêter.")
    try:
        sniff(prn=process_packet, store=False)  # store=False pour ne pas stocker les paquets en mémoire
    except KeyboardInterrupt:
        print("\nSniffer arrêté.")
