#!/bin/bash
#
# (c) 2025 by alladin@routeme.de
# simply query network security database in bash
# postgresql 

if [ $# -eq 0 ];
then
  echo "$0: Missing arguments"
  echo "usage: ./netsecdb.sh <IPv4/IPv6-Adress> for example 188.40.253.3 or 2a01:4f8:10a:1e58::4 / 2a03:2260:123:300:a62b:b0ff:feca:86da"
  exit 1
elif [ $# -gt 2 ];
then
  echo "$0: Too many arguments: $@"
  exit 1
fi

case $1 in
  *.*) echo 'Looks like IPv4'
       echo 'starting job'
       ;;
  *:*) echo 'Looks like IPv6'
       echo 'starting job'
      ;;
   *) echo 'Does not look like IP'
      echo "usage: banfail.sh ssh|pop3|plesk|smtp|ftp|dns|recidive|repeat IPv4/IPv6|CIDR"
      exit
     ;;
esac



#netcidr argument: $1
echo "Processing ..."
echo >netsecdb.txt
echo "NetsecDB Result for IP: $1" >>netsecdb.txt
echo >>netsecdb.txt


time psql postgres://user:password@localhost:5432/whois -c "SELECT netblock.id,netblock.netrange, netblock.netCIDRVAL,netblock.nethandle,netblock.netname,netblock.org_id,netblock.abusemail,left(netblock.country, 8)as country  F
ROM netblock WHERE netblock.netCIDRVAL >> '$1' ORDER BY netblock.netCIDRVAL DESC" >>netsecdb.txt

cat netsecdb.txt
