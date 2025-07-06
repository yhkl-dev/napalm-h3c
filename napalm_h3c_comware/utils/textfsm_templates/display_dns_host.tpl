Value HOSTNAME (\S+)
Value RECORD_TYPE (D|S|-)
Value TTL (\d+|-)
Value QTYPE (A|AAAA|CNAME|MX|PTR|TXT)
Value IPADDRESS ([\d\.,:A-Fa-f]+)

Start
  ^Type:\s+D:\s+Dynamic\s+S:\s+Static -> Next
  ^Total\s+number:\s+\d+ -> Next
  ^No\.\s+Host\s+name\s+Type\s+TTL\s+Query\s+type\s+IP\s+addresses -> Next
  ^\d+\s+${HOSTNAME}\s+${RECORD_TYPE}\s+${TTL}\s+${QTYPE}\s+${IPADDRESS} -> Record
