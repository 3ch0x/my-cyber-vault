The Dynamic Host Configuration Protocol (DHCP) is a fundamental network service that automates the assignment of IP addresses to devices on a network. For a Security Operations Center (SOC) analyst, understanding DHCP is crucial as it's not only a key component of network management but also a potential vector for cyberattacks. This guide delves into the workings of DHCP, its security implications, and its importance in incident response.

---

### How DHCP Works: The DORA Process

DHCP operates on a client-server model. The process of a client obtaining an IP address from a server is commonly known as the DORA process, which stands for **Discover, Offer, Request, and Acknowledge**.

- **Discover:** When a client device joins a network, it needs an IP address. It starts by broadcasting a **DHCPDISCOVER** message to all devices on the local network segment. This message is essentially the client asking, "Are there any DHCP servers out there that can give me an IP address?"
    
- **Offer:** Any DHCP server on the network that receives the discover message can respond with a **DHCPOFFER** message. This message contains a proposed IP address lease and other network configuration details like the subnet mask, default gateway, and DNS server addresses. This offer is unicast to the client's MAC address.
    
- **Request:** The client receives one or more offer messages. It typically accepts the first offer it receives by broadcasting a **DHCPREQUEST** message. This message informs the chosen server that the client is accepting its offer. It's broadcasted so that any other DHCP servers that made an offer know that their services are no longer needed.
    
- **Acknowledge:** The DHCP server that receives the request message finalizes the process by sending a **DHCPACK** (Acknowledge) message to the client. This message confirms the IP address lease and sends any remaining configuration parameters. At this point, the client is configured and can participate in the network.
    

---

### Networking and OSI Layer

DHCP is an **Application Layer (Layer 7)** protocol in the OSI model. It relies on the **User Datagram Protocol (UDP)** for its transport mechanism. DHCP servers listen on UDP port **67**, while clients use UDP port **68**.

In larger networks with multiple subnets, a single DHCP server can serve clients on different subnets with the help of a **DHCP Relay Agent**. This is typically a router or a switch configured to forward DHCP broadcast messages from clients to a DHCP server on a different subnet.

---

### A SOC Analyst's Perspective on DHCP Security

For a SOC analyst, DHCP is a double-edged sword. On one hand, its logs are invaluable for investigations. On the other, it can be exploited by malicious actors.

#### The Good: DHCP in Incident Response

DHCP server logs are a critical source of information during a security investigation. They provide a historical record of which IP address was assigned to which device (identified by its MAC address) at a specific time. This allows analysts to:

- **Identify a Compromised Device:** If an alert is triggered for a suspicious IP address, DHCP logs can help trace that IP back to the physical device's MAC address.
    
- **Track an Attacker's Movement:** By correlating DHCP logs with other logs (like firewall or proxy logs), an analyst can track an attacker's lateral movement across the network.
    

#### The Bad: Common DHCP-Based Attacks

1. **DHCP Spoofing (Rogue DHCP Server):** An attacker can set up a fake DHCP server on the network. If this rogue server responds to a client's discover message before the legitimate server, it can provide the client with a malicious configuration. For instance, it could assign a default gateway that points to an attacker-controlled machine, enabling a Man-in-the-Middle (MITM) attack where the attacker can intercept and manipulate the victim's traffic.
    
2. **DHCP Starvation Attack:** In this attack, a malicious actor floods the DHCP server with a large number of DHCPREQUEST messages using spoofed MAC addresses. The server, believing these are legitimate requests, exhausts its pool of available IP addresses. As a result, legitimate clients are unable to obtain an IP address and are denied access to the network (a form of Denial of Service).
    

#### Detecting DHCP Attacks

SOC analysts can detect these attacks by:

- **Monitoring Network Traffic:** An unusually high volume of DHCP traffic can indicate a starvation attack. Tools like Wireshark can be used to inspect DHCP packets and identify anomalies.
    
- **Analyzing Logs:** DHCP server logs can reveal signs of a starvation attack, such as a large number of lease requests from different MAC addresses in a short period. For rogue DHCP servers, network monitoring tools can be configured to alert on DHCP offer messages originating from unauthorized server IP addresses.
    
- **Utilizing Security Tools:** Many modern switches have a feature called **DHCP Snooping**, which can be configured to trust only specific ports to forward DHCP offer messages. This is a primary defense against rogue DHCP servers.
    

---

### Setting Up a DHCP Server: A Brief Overview

While SOC analysts typically don't set up DHCP servers, understanding the basic configuration can provide valuable context during investigations. Key steps include:

1. **Installation:** Installing the DHCP server role on a server operating system like Windows Server or Linux.
    
2. **Defining a Scope:** A scope is a range of IP addresses that the server is allowed to lease to clients (e.g., 192.168.1.100 to 192.168.1.200).
    
3. **Setting a Lease Duration:** This determines how long a client can use an assigned IP address before it needs to be renewed.
    
4. **Configuring Options:** This involves setting the default gateway, DNS servers, and other network parameters that will be provided to clients.
    
5. **Reservations (Optional):** You can reserve a specific IP address for a particular device's MAC address, effectively creating a static IP assignment within the DHCP framework.
    

By understanding the intricacies of DHCP, SOC analysts can better protect their networks, identify malicious activity, and respond effectively to security incidents.