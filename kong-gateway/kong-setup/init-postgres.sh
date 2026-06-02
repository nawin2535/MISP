#!/bin/bash
set -e

# อัปเดต postgresql.conf เพื่อรับการเชื่อมต่อจากทุก IP
echo "listen_addresses = '*'" >> /var/lib/postgresql/data/postgresql.conf

# อัปเดต pg_hba.conf เพื่ออนุญาตการเชื่อมต่อจากเครือข่าย Docker
echo "host all all 0.0.0.0/0 trust" >> /var/lib/postgresql/data/pg_hba.conf