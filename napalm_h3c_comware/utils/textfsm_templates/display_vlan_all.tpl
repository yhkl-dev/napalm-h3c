Value Required VLAN_ID (\d+)
Value TYPE (.*)
Value NAME (.*)
Value DESCRIPTION (.*)
Value List INTERFACES (\w+\S+\d+)

Start
  ^\s+VLAN\s+ID -> Continue.Record
  ^\s+VLAN\s+ID:\s+${VLAN_ID}
  ^\s+VLAN\s+type:\s+${TYPE}
  ^\s+Route\s+interface.*
  ^\s+IPv4\s+address.*
  ^\s+IPv4\s+subnet\s+mask.*
  ^\s+Description:\s+${DESCRIPTION}
  ^\s+Name:\s+${NAME}
  ^\s{4,}${INTERFACES}\s+ -> Continue
  ^\s{4,}\S+\s+${INTERFACES}\s+ -> Continue
