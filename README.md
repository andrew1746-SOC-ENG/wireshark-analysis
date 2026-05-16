Wireshark Analysis Report
Date: 2026-05-14
Analyst: Andrew Clark
Capture File: workcapture.pcapng 
[Download the Wireshark Capture File](./workcapture.pcapng)

1. Executive Summary
Provide a high-level overview of the findings. Traffic was captured from a wireless access point and analyzed to see traffic and type of device.
Was there a security breach, a performance bottleneck, or a specific protocol error identified?

Key Finding: Identified a high volume of TCP retransmissions originating from 192.168.1.50, suggesting a failing hardware interface or congested link.

2. Methodology & Environment
Details about how the data was captured and filtered.
Capture Duration: 2 minutes 17 seconds
Capture Filter: host 10.0.0.1
Tools Used: Wireshark v4.x, Tshark (for automated extraction)
Length: 207 kB
Hash (SHA256): 58cdafeaddab4f54e405a40dbbc2eb121d2ac2071d98953ecae383df66b8da79
Hash (SHA1):   45b68cd5ecd9f91c94999be04f70fcfef575b530
Format: Wireshark/... - pcapng
Encapsulation: Ethernet

3. Traffic Statistics
A breakdown of the protocols and endpoints involved.


Communication Summary by Protocol
UDP Traffic: The local host (172.23.119.248) initiated rapid UDP communications to destination port 443 (often indicative of HTTP/3 or QUIC-like payloads) with 142.251.156.119. 
TCP & TLS (Secure Web Traffic):
With 23.221.252.29: The hosts exchanged encrypted application data using TLS v1.2. Following the brief transaction, both ends successfully sent [FIN, ACK] flags to formally tear down the connection cleanly. 
With 17.253.21.147: The local host initiated a TCP connection using flags [SYN, ECE, CWR] targeting port 443. This was successfully established into a secure TLS v1.3 application data session. 
ARP (Address Resolution Protocol): The local router gateway (172.23.64.1) successfully broadcasted an ARP reply to map its IP to the virtual MAC address (00:00:5e:00:01:30).
4. Overview of Hosts Involved
172.23.119.248: The primary local host captured in the logs. Almost all traffic flows either to or from this IP address. 
142.251.156.119: An external host communicating via UDP. 
142.251.179.188: An external host communicating via TCP port 5228. 
23.221.252.29: An external server handling secure web traffic over port 443.
17.253.21.147: An Apple-owned external infrastructure host establishing secure connections. 
17.248.228.27: An external host using the QUIC protocol. 
IETF-VRRP-VRID_30 (172.23.64.1): The local gateway/router cluster running Virtual Router Redundancy Protocol (VRRP), responding to ARP requests. 

5. Key Findings & Analysis
5.1 Security Alerts
Indicator 1: Unauthorized SSH attempt from 203.0.113.5.
Indicator 2: Cleartext credentials observed in HTTP POST request (Frame #405).

5.2 Identified Connection Anomalies and Failures
Two notable issues were discovered in the logs:
A. Out-of-Order or Missing Segments ("Bad TCP")
Affected Hosts: 172.23.119.248 $\longleftrightarrow$ 142.251.179.188 
Details: In Frame 4, the local host sent an [ACK] segment to port 5228. The remote host responded with an ACK, but Wireshark flagged Frame 5 with the warning [TCP ACKed unseen segment] and applied a Bad TCP coloring rule. This indicates that the packet capture missed the preceding segment of the conversation, or packets were delivered significantly out-of-order. 
Retransmissions: Packet retransmissions were also flagged elsewhere in the capture (e.g., Frame 91 showing a [TCP Retransmission] from port 49603 to 443), revealing intermittent packet loss or network congestion.  
B. Definite Connection Failure (ICMP Destination Unreachable)
Affected Hosts: 172.23.119.248 $\longleftrightarrow$ 17.248.228.27 
Details: Frame 142 shows the external host attempting a QUIC Handshake with the local client. However, in Frame 271, the local host (172.23.119.248) rejected the communication by firing back an ICMP Destination unreachable (Port unreachable) message. 
Root Cause: This is a definitive connection failure. It implies that the QUIC connection attempted to communicate on a local UDP port that was either closed, not actively listening, or blocked by a local firewall policy.

6. Recommendations
Firewall Update: Block inbound traffic from 203.0.113.0/24.
Encryption: Enforce TLS 1.3 for all internal API communications.
Hardware Check: Inspect the patch cable for the database server at 192.168.1.50.


Based on the network log analysis, several engineering recommendations can be implemented to optimize the Wi-Fi hotspot's stability, eliminate connection drops, and ensure smooth traffic performance.

a. Resolve Intermittent Packet Loss & Congestion
The logs reveal multiple indicators of network degradation, including [TCP Retransmission] warnings (such as on port 49603) and [TCP ACKed unseen segment] errors. These point to wireless packet drops or heavy jitter where packets arrive out of order or are missed entirely by the recording interface.
Optimize Wi-Fi Channel Selection: Clear up airwave congestion by scanning for local interference. Move the hotspot away from over-utilized 2.4 GHz bands and transition to a less crowded 5 GHz or 6 GHz channel using wider channel spacing (e.g., 40 MHz or 80 MHz) to increase bandwidth capacity.
Adjust Quality of Service (QoS) Rules: The capture shows downstream application traffic arriving with Class Selector 2 (CS2) markings. To keep data passing smoothly without bottlenecking, configure upstream QoS rules on the router to prioritize real-time interactive traffic and match downstream performance profiles.  
2. Remediate Application Handshake Failures (QUIC / UDP Drops)
A major point of connection failure occurs when external servers attempt incoming QUIC handshakes over UDP ports (such as port 54313) . The host device explicitly rejects these attempts by sending back ICMP Destination unreachable (Port unreachable) errors .
Audit Local and Network Firewalls: Check configuration policies on host-based firewalls and router settings. Stateful inspection rules or aggressive security settings might be misidentifying traffic from secure CDN infrastructures (like Apple or Google networks) as un-tracked inbound connections and dropping the association.
Enable Consistent NAT Tracking for QUIC: Ensure the hotspot router is configured with Symmetric NAT or has a sufficiently long timeout window for UDP/QUIC states. Because QUIC functions entirely via UDP, brief drop-offs in communication can cause intermediate network devices to purge connection mapping tables, resulting in later handshake packets bouncing back with an ICMP Port Unreachable error.

3. Maintain Gateway Redundancy Integrity (VRRP)
The capture confirms that the local gateway environment safely coordinates failovers using the Virtual Router Redundancy Protocol (VRRP) , handling client discovery perfectly via local virtual MAC architecture (00:00:5e:00:01:30) .
Monitor Master/Backup VRRP Flapping: To ensure the network doesn't drop packets during unexpected routing transitions, track the VRRP router cluster health log. Set conservative advertisement timers to protect clients from experiencing packet loss if a temporary drop in wireless signal quality mimics a gateway breakdown.
Based on a deep security inspection of the network log file (wificapture.txt), there are no active Indicators of Compromise (IOCs) or signs of malicious activity. The anomalies identified in the packet trace are characteristic of standard network behaviors, benign infrastructure processes, or routine transient wireless connection issues.
Below is a breakdown of why the flagged indicators do not constitute IOCs, confirming that the traffic is clean:
1. External IP Destinations (Verified Clean)
Malicious traffic typically reaches out to known Command and Control (C2) servers, dynamic DNS providers, or un-reputed networks. The destination IP addresses in this capture belong strictly to major, trusted public infrastructures:
142.251.156.119 & 142.251.179.188: Google Infrastructure (commonly used for Android services, Google Workspace, Chrome background sync, or Firebase Cloud Messaging).
23.221.252.29: Akamai Technologies Content Delivery Network (CDN), used globally by thousands of mainstream companies to host safe, legitimate web assets.
17.253.21.147, 17.253.20.49, & 17.248.228.27: Apple Infrastructure (used for standard iOS/macOS push notifications, iCloud synchronization, or device telemetry).

2. The ICMP "Port Unreachable" Behavior (Benign Firewalls/Service Drops)
While ICMP Destination Unreachable (Port Unreachable) messages can sometimes indicate a scanner probing ports, in this context, it represents a routine application-level mismatch:
An external Apple endpoint attempted to send a QUIC packet back to the local client host on a high ephemeral UDP port.
Because UDP is connectionless, if the local application closed or the state table entry expired, the host OS returns an ICMP port unreachable message.
This is completely normal behavior for mobile or wireless devices shifting states and does not map to a scanning or data exfiltration IOC.

3. "Bad TCP" Warnings (Physical Layer Artifacts)
Wireshark flags like [TCP ACKed unseen segment] or [TCP Retransmission] are purely indicators of wireless layer unreliability (such as temporary packet drops, Wi-Fi interference, or the packet capture interface failing to keep up with the physical network adapter). They are network performance issues rather than a protocol manipulation or spoofing attack.
Summary
Malicious Domains/IPs: None detected.
Unauthorized Protocols/Tunnels: None detected (all web traffic utilizes standard, encrypted TLS 1.2/1.3 or QUIC).
Suspicious Local Broadcasts: None detected (the ARP activity is normal gateway tracking).
The log shows a routine, secure session interacting with legitimate cloud providers.


