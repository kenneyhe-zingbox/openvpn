#!/bin/bash
cat <<QEND | sudo docker exec -i mysql-server mysql -ureadonly vpndb
select mac_address from vpndb.zingbox_inventory
QEND
