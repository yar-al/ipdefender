from scapy.all import ARP, Ether
from ipdefender import load_config
from scapy.all import sniff, ARP, Ether, sendp

protected_ips, interface = load_config()
"""Запуск IPDefender и проверка ответа на поддельный GARP"""

nice_arp = Ether() / ARP(
    op=2,
    psrc="192.168.1.10",
    hwsrc="AA:BB:CC:DD:EE:FF",
    pdst="192.168.1.10"
)

fake_arp = Ether() / ARP(
    op=2,
    psrc="192.168.1.10",
    hwsrc="11:22:33:44:55:66",
    pdst="192.168.1.10"
)

sendp(nice_arp, iface=interface, verbose=True)
sendp(fake_arp, iface=interface, verbose=True)
#sendp(nice_arp, iface=interface, verbose=False)
#sendp(fake_arp, iface=interface, verbose=False)

packets = sniff(
    filter="arp and host 192.168.1.10",
    count=2,
    timeout=5,
    iface=interface
)