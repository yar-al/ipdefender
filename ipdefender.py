from scapy.all import Ether, ARP, sniff, sendp
from scapy.layers.l2 import ARP
import yaml
import logging

# Настройка логов
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def load_config():
    """Загрузка конфигурации из файла config.yaml"""
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
            protected = {entry["ip"]: entry["mac"] for entry in config["protected_ips"]}
            interface = config["interface"]
            return protected, interface
    except Exception as e:
        logging.error(f"Error in config: {e}")
        exit(1)

def arp_callback(pkt, protected_ips, interface):
    """Обработка ARP-пакетов"""
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        # Проверка на Gratuitous ARP (op=1, sender IP == target IP)
        if (arp.op == 1 or arp.op == 2) and arp.psrc == arp.pdst:
            if arp.psrc in protected_ips:
                correct_mac = protected_ips[arp.psrc]
                if arp.hwsrc.lower() != correct_mac.lower():
                    logging.warning(f"Detected false GARP for {arp.psrc}. Sending ARP reply...")
                    # Формирование корректирующего ARP-ответа (broadcast)
                    eth = Ether(dst="ff:ff:ff:ff:ff:ff")
                    reply = ARP(
                        op=2,  # ARP-ответ
                        psrc=arp.psrc,
                        hwsrc=correct_mac,
                        pdst=arp.psrc
                    )
                    sendp(eth / reply, iface=interface, verbose=True)

def main():
    protected_ips, interface = load_config()
    logging.info(f"Защищаемые IP-MAC: {protected_ips}")
    logging.info(f"Слушаю интерфейс: {interface}")
    # Захват ARP-пакетов с фильтром
    sniff(
        filter="arp",          # Фильтр ARP-трафика
        iface=interface,
        prn=lambda pkt: arp_callback(pkt, protected_ips, interface),
        store=0                # Не сохранять пакеты в памяти
    )

if __name__ == "__main__":
    main()