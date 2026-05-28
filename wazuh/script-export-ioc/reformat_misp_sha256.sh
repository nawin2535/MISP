cp /var/ossec/etc/lists/misp_sha256 /var/ossec/etc/lists/misp_sha256.bak
cp /var/ossec/etc/lists/malicious-ioc/malware-hashes /var/ossec/etc/lists/malicious-ioc/malware-hashes.bak
awk -F: '{print "SHA256=" toupper($1) ":" $2}' \
  /var/ossec/etc/lists/misp_sha256.bak \
  > /var/ossec/etc/lists/misp_sha256_sysmonuse
awk -F: '{print "SHA256=" toupper($1) ":" $2}' \
  /var/ossec/etc/lists/malicious-ioc/malware-hashes.bak \
  > /var/ossec/etc/lists/malicious-ioc/malware-hashes_sha256_sysmonuse