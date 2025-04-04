from scapy.all import ARP, Ether
from ipdefender import arp_callback, load_config
import pytest
from scapy.all import sniff, ARP, Ether, sendp

def test_arp_callback_valid_mac(mocker):
    """Gratuitous ARP с правильным MAC — ответ не отправляется"""
    protected_ips = load_config()
    mock_sendp = mocker.patch("ipdefender.sendp")
    
    arp_pkt = ARP(
        op=1,  # ARP-запрос (Gratuitous)
        psrc="192.168.1.10",
        hwsrc="aa:bb:cc:dd:ee:ff",
        pdst="192.168.1.10"
    )
    
    arp_callback(arp_pkt, protected_ips, "Ethernet")
    mock_sendp.assert_not_called()

def test_arp_callback_invalid_mac(mocker):
    """Gratuitous ARP с неправильным MAC — отправляется ответ"""
    protected_ips = {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}
    mock_sendp = mocker.patch("ipdefender.sendp")
    
    # Создаем пакет с неверным MAC
    arp_pkt = ARP(
        op=1,
        psrc="192.168.1.10",
        hwsrc="11:22:33:44:55:66",  # Неверный MAC
        pdst="192.168.1.10"
    )
    
    arp_callback(arp_pkt, protected_ips, "Ethernet")
    mock_sendp.assert_called_once()
    
    # Проверяем, что отправленный пакет корректен
    sent_packet = mock_sendp.call_args[0][0]
    assert sent_packet[ARP].psrc == "192.168.1.10"
    assert sent_packet[ARP].hwsrc == "aa:bb:cc:dd:ee:ff"

def test_arp_callback_non_protected_ip(mocker):
    """Пакет с незащищаемым IP игнорируется"""
    protected_ips = {"192.168.1.20": "aa:bb:cc:dd:ee:ff"}
    mock_sendp = mocker.patch("ipdefender.sendp")
    
    arp_pkt = ARP(
        op=1,
        psrc="192.168.1.10",  # Not defended IP
        hwsrc="11:22:33:44:55:66",
        pdst="192.168.1.10"
    )
    
    arp_callback(arp_pkt, protected_ips, "Ethernet")
    mock_sendp.assert_not_called()

@pytest.mark.integration
def test_garp_protection():
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
    
    #assert len(packets) == 1
    #assert packets[0][ARP].hwsrc == "aa:bb:cc:dd:ee:ff"