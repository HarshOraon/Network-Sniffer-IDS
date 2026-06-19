window.NETWORK_DASHBOARD_DATA = {
  "generatedAt": "2026-06-19T21:28:23+05:30",
  "source": {
    "name": "live_capture_admin.pcap",
    "path": "C:\\Users\\oaoha\\OneDrive\\Desktop\\Source\\live_capture_admin.pcap"
  },
  "metadata": {
    "path": "C:\\Users\\oaoha\\OneDrive\\Desktop\\Source\\live_capture_admin.pcap",
    "fileName": "live_capture_admin.pcap",
    "fileSize": 708,
    "version": "2.4",
    "thiszone": 0,
    "sigfigs": 0,
    "snaplen": 65535,
    "linktype": 101,
    "timestampResolution": "microseconds"
  },
  "summary": {
    "totalPackets": 5,
    "totalBytes": 604,
    "durationSeconds": 0.117,
    "startTime": "2026-06-18T13:46:04",
    "endTime": "2026-06-18T13:46:05",
    "packetsPerSecond": 42.65,
    "bytesPerSecond": 5152.53,
    "protocols": [
      {
        "name": "UDP",
        "count": 5,
        "bytes": 604
      }
    ],
    "services": [
      {
        "name": "DNS",
        "count": 5
      }
    ],
    "topEndpoints": [
      {
        "name": "10.99.203.54:53",
        "count": 5,
        "bytes": 604
      },
      {
        "name": "10.99.203.163:60854",
        "count": 2,
        "bytes": 254
      },
      {
        "name": "10.99.203.163:60852",
        "count": 2,
        "bytes": 254
      },
      {
        "name": "10.99.203.163:65242",
        "count": 1,
        "bytes": 96
      }
    ],
    "topConversations": [
      {
        "name": "10.99.203.163:60854 <-> 10.99.203.54:53",
        "count": 2,
        "bytes": 254
      },
      {
        "name": "10.99.203.163:60852 <-> 10.99.203.54:53",
        "count": 2,
        "bytes": 254
      },
      {
        "name": "10.99.203.163:65242 <-> 10.99.203.54:53",
        "count": 1,
        "bytes": 96
      }
    ],
    "timeline": [
      {
        "time": "13:46:04",
        "packets": 2,
        "bytes": 192
      },
      {
        "time": "13:46:05",
        "packets": 3,
        "bytes": 412
      }
    ],
    "insights": [
      {
        "level": "notice",
        "title": "Layer-3 capture",
        "body": "This pcap stores raw IP packets, so Ethernet MAC addresses and ARP traffic are not available."
      },
      {
        "level": "info",
        "title": "All packets are UDP",
        "body": "The sample is narrowly focused: 5 of 5 packets use UDP."
      },
      {
        "level": "info",
        "title": "DNS activity detected",
        "body": "5 packet(s) use port 53, which usually means name-resolution traffic."
      },
      {
        "level": "notice",
        "title": "Short capture window",
        "body": "Capture for 30-60 seconds to see a more representative traffic mix."
      }
    ]
  },
  "packets": [
    {
      "index": 1,
      "timestamp": 1781770564.991126,
      "time": "2026-06-18T13:46:04.991",
      "length": 96,
      "includedLength": 96,
      "originalLength": 96,
      "layer2": "RawIP",
      "network": "IPv4",
      "transport": "UDP",
      "protocol": "RawIP/IPv4/UDP",
      "src": "10.99.203.163",
      "dst": "10.99.203.54",
      "srcPort": 60854,
      "dstPort": 53,
      "srcEndpoint": "10.99.203.163:60854",
      "dstEndpoint": "10.99.203.54:53",
      "service": "DNS",
      "info": "payload=68",
      "hexPreview": "45 00 00 60 b3 89 00 00 80 11 db 63 0a 63 cb a3 0a 63 cb 36 ed b6 00 35 00 4c b1 79 4b b7 01 00"
    },
    {
      "index": 2,
      "timestamp": 1781770564.992496,
      "time": "2026-06-18T13:46:04.992",
      "length": 96,
      "includedLength": 96,
      "originalLength": 96,
      "layer2": "RawIP",
      "network": "IPv4",
      "transport": "UDP",
      "protocol": "RawIP/IPv4/UDP",
      "src": "10.99.203.163",
      "dst": "10.99.203.54",
      "srcPort": 60852,
      "dstPort": 53,
      "srcEndpoint": "10.99.203.163:60852",
      "dstEndpoint": "10.99.203.54:53",
      "service": "DNS",
      "info": "payload=68",
      "hexPreview": "45 00 00 60 b3 8a 00 00 80 11 db 62 0a 63 cb a3 0a 63 cb 36 ed b4 00 35 00 4c 8d c0 6f 57 01 00"
    },
    {
      "index": 3,
      "timestamp": 1781770565.051304,
      "time": "2026-06-18T13:46:05.051",
      "length": 158,
      "includedLength": 158,
      "originalLength": 158,
      "layer2": "RawIP",
      "network": "IPv4",
      "transport": "UDP",
      "protocol": "RawIP/IPv4/UDP",
      "src": "10.99.203.54",
      "dst": "10.99.203.163",
      "srcPort": 53,
      "dstPort": 60854,
      "srcEndpoint": "10.99.203.54:53",
      "dstEndpoint": "10.99.203.163:60854",
      "service": "DNS",
      "info": "payload=130",
      "hexPreview": "45 00 00 9e 78 cb 40 00 40 11 15 e4 0a 63 cb 36 0a 63 cb a3 00 35 ed b6 00 8a c4 ec 4b b7 81 80"
    },
    {
      "index": 4,
      "timestamp": 1781770565.08413,
      "time": "2026-06-18T13:46:05.084",
      "length": 158,
      "includedLength": 158,
      "originalLength": 158,
      "layer2": "RawIP",
      "network": "IPv4",
      "transport": "UDP",
      "protocol": "RawIP/IPv4/UDP",
      "src": "10.99.203.54",
      "dst": "10.99.203.163",
      "srcPort": 53,
      "dstPort": 60852,
      "srcEndpoint": "10.99.203.54:53",
      "dstEndpoint": "10.99.203.163:60852",
      "service": "DNS",
      "info": "payload=130",
      "hexPreview": "45 00 00 9e 78 d3 40 00 40 11 15 dc 0a 63 cb 36 0a 63 cb a3 00 35 ed b4 00 8a 9f d3 6f 57 81 80"
    },
    {
      "index": 5,
      "timestamp": 1781770565.10835,
      "time": "2026-06-18T13:46:05.108",
      "length": 96,
      "includedLength": 96,
      "originalLength": 96,
      "layer2": "RawIP",
      "network": "IPv4",
      "transport": "UDP",
      "protocol": "RawIP/IPv4/UDP",
      "src": "10.99.203.163",
      "dst": "10.99.203.54",
      "srcPort": 65242,
      "dstPort": 53,
      "srcEndpoint": "10.99.203.163:65242",
      "dstEndpoint": "10.99.203.54:53",
      "service": "DNS",
      "info": "payload=68",
      "hexPreview": "45 00 00 60 b3 8b 00 00 80 11 db 61 0a 63 cb a3 0a 63 cb 36 fe da 00 35 00 4c 41 ff aa 0d 01 00"
    }
  ]
};
