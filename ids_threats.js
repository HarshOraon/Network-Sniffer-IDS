window.IDS_THREAT_DATA = {
  "generatedAt": "2026-06-19T21:24:56+05:30",
  "totalAlerts": 2,
  "bySeverity": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 2,
    "LOW": 0
  },
  "byRule": [
    {
      "rule": "DNS Tunneling",
      "count": 2
    }
  ],
  "topAttackers": [
    {
      "ip": "10.228.69.163",
      "count": 1
    },
    {
      "ip": "10.228.69.143",
      "count": 1
    }
  ],
  "alerts": [
    {
      "timestamp": 1781884475.524935,
      "time": "2026-06-19T21:24:35.524",
      "rule": "DNS Tunneling",
      "severity": "MEDIUM",
      "srcIp": "10.228.69.163",
      "dstIp": "10.228.69.143",
      "detail": "15 DNS packets in 5.0s (possible data exfil)",
      "packetIndices": [
        66
      ]
    },
    {
      "timestamp": 1781884475.563109,
      "time": "2026-06-19T21:24:35.563",
      "rule": "DNS Tunneling",
      "severity": "MEDIUM",
      "srcIp": "10.228.69.143",
      "dstIp": "10.228.69.163",
      "detail": "15 DNS packets in 5.0s (possible data exfil)",
      "packetIndices": [
        70
      ]
    }
  ]
};
