#!/usr/bin/env python3
"""
DHCP Security Inspector
Implements port-based DHCP message filtering and inspection
"""

import struct
import socket
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Set, Optional, Tuple

class DHCPMessageType(Enum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8

class PortTrustLevel(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"

@dataclass
class DHCPMessage:
    op: int  # 1 = BOOTREQUEST, 2 = BOOTREPLY
    htype: int  # Hardware type
    hlen: int  # Hardware address length
    hops: int
    xid: int  # Transaction ID
    secs: int
    flags: int
    ciaddr: str  # Client IP address
    yiaddr: str  # Your IP address
    siaddr: str  # Server IP address
    giaddr: str  # Gateway IP address
    chaddr: str  # Client hardware address
    message_type: Optional[DHCPMessageType] = None
    
class DHCPSecurityInspector:
    def __init__(self):
        self.trusted_ports: Set[int] = set()
        self.untrusted_ports: Set[int] = set()
        self.stats = {
            'forwarded': 0,
            'discarded': 0,
            'inspected': 0
        }
    
    def configure_port(self, port_id: int, trust_level: PortTrustLevel):
        """Configure a port's trust level"""
        if trust_level == PortTrustLevel.TRUSTED:
            self.trusted_ports.add(port_id)
            self.untrusted_ports.discard(port_id)
        else:
            self.untrusted_ports.add(port_id)
            self.trusted_ports.discard(port_id)
    
    def parse_dhcp_message(self, packet_data: bytes) -> Optional[DHCPMessage]:
        """Parse DHCP message from packet data"""
        try:
            # Skip Ethernet (14 bytes) and IP headers (20 bytes) and UDP header (8 bytes)
            dhcp_offset = 42
            if len(packet_data) < dhcp_offset + 240:
                return None
            
            dhcp_data = packet_data[dhcp_offset:]
            
            # Parse DHCP header (first 240 bytes)
            header = struct.unpack('!BBBBIHH4s4s4s4s16s', dhcp_data[:44])
            
            op, htype, hlen, hops, xid, secs, flags = header[:7]
            ciaddr = socket.inet_ntoa(header[7])
            yiaddr = socket.inet_ntoa(header[8])
            siaddr = socket.inet_ntoa(header[9])
            giaddr = socket.inet_ntoa(header[10])
            chaddr_bytes = header[11]
            
            # Convert hardware address to MAC format
            chaddr = ':'.join(f'{b:02x}' for b in chaddr_bytes[:6])
            
            # Parse DHCP options to find message type
            message_type = self._parse_dhcp_options(dhcp_data[240:])
            
            return DHCPMessage(
                op=op, htype=htype, hlen=hlen, hops=hops,
                xid=xid, secs=secs, flags=flags,
                ciaddr=ciaddr, yiaddr=yiaddr, siaddr=siaddr, giaddr=giaddr,
                chaddr=chaddr, message_type=message_type
            )
        except Exception as e:
            print(f"Error parsing DHCP message: {e}")
            return None
    
    def _parse_dhcp_options(self, options_data: bytes) -> Optional[DHCPMessageType]:
        """Parse DHCP options to find message type"""
        i = 4  # Skip magic cookie
        while i < len(options_data):
            if options_data[i] == 255:  # End option
                break
            elif options_data[i] == 0:  # Pad option
                i += 1
                continue
            
            option_code = options_data[i]
            option_length = options_data[i + 1] if i + 1 < len(options_data) else 0
            
            if option_code == 53 and option_length == 1:  # DHCP Message Type
                msg_type_value = options_data[i + 2]
                try:
                    return DHCPMessageType(msg_type_value)
                except ValueError:
                    return None
            
            i += 2 + option_length
        
        return None
    
    def extract_source_mac(self, packet_data: bytes) -> Optional[str]:
        """Extract source MAC address from Ethernet frame"""
        if len(packet_data) < 14:
            return None
        
        src_mac = packet_data[6:12]
        return ':'.join(f'{b:02x}' for b in src_mac)
    
    def is_dhcp_server_message(self, message: DHCPMessage) -> bool:
        """Check if message is from DHCP server (BOOTREPLY)"""
        return message.op == 2
    
    def is_dhcp_client_message(self, message: DHCPMessage) -> bool:
        """Check if message is from DHCP client (BOOTREQUEST)"""
        return message.op == 1
    
    def inspect_dhcp_message(self, packet_data: bytes, source_port: int, 
                           source_mac: str) -> Tuple[bool, str]:
        """
        Main inspection logic
        Returns: (should_forward, reason)
        """
        # Check port trust level
        if source_port in self.trusted_ports:
            self.stats['forwarded'] += 1
            return True, "Trusted port - forwarded without inspection"
        
        if source_port not in self.untrusted_ports:
            # Port not configured, treat as untrusted by default
            self.untrusted_ports.add(source_port)
        
        # Parse DHCP message
        dhcp_msg = self.parse_dhcp_message(packet_data)
        if not dhcp_msg:
            self.stats['discarded'] += 1
            return False, "Invalid DHCP message format"
        
        self.stats['inspected'] += 1
        
        # Check if it's a server message (BOOTREPLY)
        if self.is_dhcp_server_message(dhcp_msg):
            # Server messages on untrusted ports should be discarded
            self.stats['discarded'] += 1
            return False, "DHCP server message on untrusted port"
        
        # For client messages (BOOTREQUEST), check DISCOVER and REQUEST
        if dhcp_msg.message_type in [DHCPMessageType.DISCOVER, DHCPMessageType.REQUEST]:
            # Extract source MAC from frame
            frame_src_mac = self.extract_source_mac(packet_data)
            if not frame_src_mac:
                self.stats['discarded'] += 1
                return False, "Cannot extract source MAC from frame"
            
            # Compare frame source MAC with DHCP CHADDR field
            if frame_src_mac.lower() == dhcp_msg.chaddr.lower():
                self.stats['forwarded'] += 1
                return True, "MAC addresses match - forwarded"
            else:
                self.stats['discarded'] += 1
                return False, f"MAC mismatch: Frame={frame_src_mac}, CHADDR={dhcp_msg.chaddr}"
        
        # Other client message types are forwarded
        self.stats['forwarded'] += 1
        return True, "Client message - forwarded"
    
    def get_statistics(self) -> Dict:
        """Get inspection statistics"""
        return self.stats.copy()

# Test Framework
class DHCPSecurityTester:
    def __init__(self):
        self.inspector = DHCPSecurityInspector()
        self.test_results = []
    
    def create_test_packet(self, src_mac: str, dhcp_chaddr: str, 
                          message_type: DHCPMessageType, op: int = 1) -> bytes:
        """Create a test DHCP packet"""
        # Ethernet header (14 bytes)
        dst_mac = bytes.fromhex('ffffffffffff')  # Broadcast
        src_mac_bytes = bytes.fromhex(src_mac.replace(':', ''))
        ethertype = struct.pack('!H', 0x0800)  # IPv4
        
        # IP header (20 bytes) - simplified
        ip_header = b'\x45\x00\x01\x48\x00\x00\x00\x00\x40\x11\x00\x00'
        ip_header += socket.inet_aton('192.168.1.100')  # Source IP
        ip_header += socket.inet_aton('255.255.255.255')  # Dest IP
        
        # UDP header (8 bytes)
        udp_header = struct.pack('!HHHH', 68, 67, 308, 0)  # src_port, dst_port, length, checksum
        
        # DHCP header
        htype = 1  # Ethernet
        hlen = 6   # MAC address length
        hops = 0
        xid = 0x12345678
        secs = 0
        flags = 0x8000  # Broadcast flag
        
        ciaddr = socket.inet_aton('0.0.0.0')
        yiaddr = socket.inet_aton('0.0.0.0')
        siaddr = socket.inet_aton('0.0.0.0')
        giaddr = socket.inet_aton('0.0.0.0')
        
        # CHADDR (16 bytes, only first 6 used for MAC)
        chaddr_bytes = bytes.fromhex(dhcp_chaddr.replace(':', ''))
        chaddr_padded = chaddr_bytes + b'\x00' * (16 - len(chaddr_bytes))
        
        dhcp_header = struct.pack('!BBBBIHH4s4s4s4s16s',
                                 op, htype, hlen, hops, xid, secs, flags,
                                 ciaddr, yiaddr, siaddr, giaddr, chaddr_padded)
        
        # Server name and boot file (192 bytes of zeros)
        sname_file = b'\x00' * 192
        
        # DHCP options
        magic_cookie = b'\x63\x82\x53\x63'
        msg_type_option = struct.pack('!BBB', 53, 1, message_type.value)
        end_option = b'\xff'
        
        # Pad to minimum size
        options = magic_cookie + msg_type_option + end_option
        options += b'\x00' * (68 - len(options))  # Pad to minimum DHCP size
        
        # Assemble packet
        packet = (dst_mac + src_mac_bytes + ethertype + 
                 ip_header + udp_header + dhcp_header + 
                 sname_file + options)
        
        return packet
    
    def run_test(self, test_name: str, packet: bytes, source_port: int, 
                expected_forward: bool, expected_reason_contains: str = ""):
        """Run a single test case"""
        src_mac = self.inspector.extract_source_mac(packet)
        should_forward, reason = self.inspector.inspect_dhcp_message(
            packet, source_port, src_mac or "unknown"
        )
        
        passed = should_forward == expected_forward
        if expected_reason_contains:
            passed = passed and expected_reason_contains.lower() in reason.lower()
        
        result = {
            'test_name': test_name,
            'passed': passed,
            'expected_forward': expected_forward,
            'actual_forward': should_forward,
            'reason': reason
        }
        
        self.test_results.append(result)
        return result
    
    def run_all_tests(self):
        """Run comprehensive test suite"""
        print("DHCP Security Inspector Test Suite")
        print("=" * 50)
        
        # Configure test ports
        self.inspector.configure_port(1, PortTrustLevel.TRUSTED)
        self.inspector.configure_port(2, PortTrustLevel.UNTRUSTED)
        self.inspector.configure_port(3, PortTrustLevel.UNTRUSTED)
        
        # Test 1: Trusted port - should forward without inspection
        packet1 = self.create_test_packet('aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:99', 
                                         DHCPMessageType.DISCOVER)
        self.run_test("Trusted port test", packet1, 1, True, "trusted")
        
        # Test 2: Untrusted port, matching MACs - should forward
        packet2 = self.create_test_packet('aa:bb:cc:dd:ee:02', 'aa:bb:cc:dd:ee:02', 
                                         DHCPMessageType.DISCOVER)
        self.run_test("Untrusted port - MAC match", packet2, 2, True, "match")
        
        # Test 3: Untrusted port, mismatched MACs - should discard
        packet3 = self.create_test_packet('aa:bb:cc:dd:ee:03', 'aa:bb:cc:dd:ee:99', 
                                         DHCPMessageType.REQUEST)
        self.run_test("Untrusted port - MAC mismatch", packet3, 2, False, "mismatch")
        
        # Test 4: Server message on untrusted port - should discard
        packet4 = self.create_test_packet('aa:bb:cc:dd:ee:04', 'aa:bb:cc:dd:ee:04', 
                                         DHCPMessageType.OFFER, op=2)
        self.run_test("Server message on untrusted port", packet4, 3, False, "server")
        
        # Test 5: Other client messages should forward (even with MAC mismatch)
        packet5 = self.create_test_packet('aa:bb:cc:dd:ee:05', 'aa:bb:cc:dd:ee:99', 
                                         DHCPMessageType.RELEASE)
        self.run_test("RELEASE message", packet5, 2, True, "forwarded")
        
        # Print results
        print(f"\nTest Results:")
        print("-" * 50)
        passed_count = 0
        for result in self.test_results:
            status = "PASS" if result['passed'] else "FAIL"
            print(f"{result['test_name']}: {status}")
            print(f"  Expected: {result['expected_forward']}, Got: {result['actual_forward']}")
            print(f"  Reason: {result['reason']}")
            print()
            if result['passed']:
                passed_count += 1
        
        print(f"Tests passed: {passed_count}/{len(self.test_results)}")
        print(f"\nInspection Statistics:")
        stats = self.inspector.get_statistics()
        for key, value in stats.items():
            print(f"  {key.capitalize()}: {value}")

if __name__ == "__main__":
    # Run the test suite
    tester = DHCPSecurityTester()
    tester.run_all_tests()