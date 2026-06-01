Splunk Network SOC monitoring Mac lab\
\
The goal of this Network SOC Monitoring Lab was to ingest real network connection data collected from a personal MacBook Pro into Splunk Enterprise and simulate a Security Operations Center (SOC) monitoring workflow. Using the mac_netstat.log dataset, network activity was indexed, searched, analyzed, and visualized to gain visibility into active network connections, listening services, and communication patterns. The lab focused on transforming raw network data into actionable security information through dashboards, reports, visualizations, alerts, detection rules, and threat-hunting queries.

Throughout the lab, Splunk was used to monitor network events, identify established connections, investigate remote IP communications, review listening services, and develop basic detection and monitoring capabilities. This exercise provided hands-on experience with Splunk Enterprise, Security Information and Event Management (SIEM) workflows, network monitoring, and SOC analyst responsibilities while demonstrating how network telemetry can be leveraged for security operations, incident investigation, and threat hunting.

# Network Index (index=network)

Network data shows:

who is communicating,\
where they are communicating,\
which ports are being used,\
whether connections are established or listening.

dataset: mac_netstat.log came from netstat -an

192.168.1.193:59061 → 3.221.141.237:443\
192.168.1.193:62189 → 104.18.32.47:443

Search bar: index=network or index=network \| stats count by host

SOC analysts use network data to:

identify active connections,\
investigate remote IPs,\
detect unusual traffic,\
identify communication patterns,\
investigate incidents.

**Step 1 — Create Network Index**

Setting→ Indexes → New Index. Create index Name: network

default:

\$SPLUNK_DB/network/db\
\$SPLUNK_DB/network/colddb\
\$SPLUNK_DB/network/thaweddb



## Step 2 — Upload Network Dataset

Settings → Add Data → Upload: mac_netstat.log

Index: network\
Sourcetype: mac_netstat

Review → Submit

\
**Step 3 — Verify Network Ingestion**

Search bar: index=network

Purpose: confirm Splunk received the network dataset.

**Step 4 — Verify Event Count**

Search bar: index=network \| stats count\
Purpose: count all ingested network events.

**Step 5 — Show Network Events in Table**


Search bar:\
\
index=network\
\| table \_time host source sourcetype \_raw

Purpose: display clean network dataset events.

\
**Step 6 — Find Established Network Connections**


Search bar: index=network ESTABLISHED

Purpose: identify active network sessions.

**Step 7 — Count Established Connections**


Search bar: index=network ESTABLISHED \| stats count\

Purpose: count active established connections.\

**Step 8 — Find Listening Ports**

Search bar: index=network LISTEN

Purpose: identify services listening for connections.


**Step 9 — Count Listening Services**


Search bar: index=network LISTEN\
\| stats count

Purpose: count exposed/listening services.


Step 10 — Extract Remote Addresses\


Search bar:

index=network ESTABLISHED\
\| rex field=\_raw "\s(?\<remote_ip\>\d{1,3}(?:\\\d{1,3}){3})\\\d+\s+ESTABLISHED"\
\| stats count by remote_ip\
\| sort - count

Purpose: Identify remote IP addresses found in established network connections. In this dataset, the result 127.0.0.1 shows local loopback communication, meaning the Mac was communicating with itself through local services.\

**Step 11 — Visualization**\

Search bar:

index=network ESTABLISHED\
\| rex field=\_raw "\s(?\<remote_ip\>\d{1,3}(?:\\\d{1,3}){3})\\\d+\s+ESTABLISHED"\
\| stats count by remote_ip\
\| sort - count

Purpose: showing top remote IP connections from extracted remote address.

\
**Step 12 — Save as Report**\
\**
Report title: Network Remote IP Connection Report

Description: This report identifies remote IP addresses communicating with the MacBook Pro network dataset.\
\


Step 13 — Save as Dashboard Panel from Extract Remote Addresses


Dashboard title: Network SOC Monitoring Dashboard

Panel title: Top Remote Network Connections

Description: A Splunk dashboard was created to visualize network connection activity from the mac_netstat.log dataset. The dashboard provides SOC analysts with a centralized view of network services, listening ports, connection status, and network monitoring information for investigation and threat-hunting purposes.


**Step 14 — Create Alert for Established Connections**


Search bar:\
\
index=network ESTABLISHED\
\| stats count\
\| where count \> 10

Alert title: High Number of Established Network Connections

Purpose: alert when active connections exceed a threshold.\

Description: This alert was created to identify established network connections within the network dataset and notify analysts of potentially active network communication requiring further investigation.\

**Step 15 — Create Simple Network Detection Rule**

Search bar:

index=network ESTABLISHED\
\| rex field=\_raw "\s(?\<remote_ip\>\d{1,3}(?:\\\d{1,3}){3})\\\d+\s+ESTABLISHED"\
\| stats count by remote_ip\
\| where count \> 5

Detection name: Repeated Remote Network Communication Detection

Purpose: detect repeated communication with the same remote IP.\

A detection query was created to identify IP addresses associated with established network connections. The query extracted remote IP addresses from the network dataset and counted how many times each IP appeared. When the threshold was set to count \> 5, no results were returned because the dataset contained only a single matching established connection.\

After adjusting the threshold to count \>= 1, the query successfully returned one result with the IP address 127.0.0.1. This IP represents the localhost (loopback) interface, indicating that the observed established connection was local to the MacBook Pro rather than communication with an external Internet host. This exercise demonstrated how detection thresholds affect query results and highlighted the importance of tuning detection logic based on the size and characteristics of the available dataset.\
\
**Step 16 — Threat Hunting Query**

Search bar:

index=network\
\| search ESTABLISHED OR LISTEN\
\| table \_time host sourcetype \_raw

 Purpose: review active and listening network activity for hunting.\
\
\

**\_time:** The timestamp when Splunk indexed the network dataset.

**Host:** This identifies your MacBook Pro as the source of the network information.

**Sourcetype:** The type of data ingested into Splunk. mac_netstat. Indicates the data originated from the netstat network command.

**tcp4:** Protocol and IP version. Transmission Control Protocol (tcp).IPv4.

**Recv-Q:** eceive Queue. Shows bytes received by the operating system but not yet processed by the application. Zero usually means no backlog.

**Send-Q:** Send Queue. Shows bytes waiting to be transmitted. Zero usually means traffic is flowing normally.

**Local Address:** IP address and port on the Mac. 192.168.1.193. Port: 59061

**Foreign Address:** Remote IP address and port communicating with Mac.3.221.141.237.443

Remote IP:3.221.141.237

Remote Port:443 (HTTPS/TLS)

**State = ESTABLISHED:** Indicates an active TCP connection exists between your Mac and another system. It Means data can be exchanged between both systems.

**State = LISTEN:**Indicates a service is waiting for incoming connections. It Shows a service is listening on port 22 (SSH).

### Threat Hunting Observation

The dataset contains both:

127.0.0.1

(localhost/loopback traffic)

and external Internet communications such as:

3.221.141.237:443\
20.33.3.2:443\
23.49.251.240:443\
172.253.139.188:5228

This threat-hunting query was used to review active (ESTABLISHED) and listening (LISTEN) network connections from the MacBook Pro dataset. The results provided visibility into protocols, local and remote IP addresses, ports, connection states, and network communication patterns, enabling investigation of both local services and external Internet connections.\
\
Step 17 — Network Lab Completion Query


Search bar:

index=network\
\| stats count by sourcetype source host

Purpose: confirm final dataset visibility in Splunk.\

