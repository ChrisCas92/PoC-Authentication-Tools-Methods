#!/bin/bash
# This script lists all user entries in the directory
# It retrieves basic details for each user in the Users organizational unit

echo "Listing all users in the directory..."

docker exec openldap ldapsearch -H ldap://localhost:389 -x \
    -D "cn=ServiceAccount,ou=Users,dc=example,dc=com" \
    -w servicepassword \
    -b "ou=Users,dc=example,dc=com" \
    -s one \
    "(objectClass=inetOrgPerson)" \
    cn sAMAccountName mail displayName

if [ $? -eq 0 ]; then
    echo "User listing completed successfully."
else
    echo "ERROR: List operation failed. Check the LDAP server logs for details."
fi