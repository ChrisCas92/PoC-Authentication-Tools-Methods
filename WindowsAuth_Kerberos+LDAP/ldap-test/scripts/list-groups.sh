#!/bin/bash
# This script lists all groups in the directory
# It shows information about each group including its description

echo "Listing all groups in the directory..."

docker exec openldap ldapsearch -H ldap://localhost:389 -x \
    -D "cn=ServiceAccount,ou=Users,dc=example,dc=com" \
    -w servicepassword \
    -b "ou=Groups,dc=example,dc=com" \
    -s one \
    "(objectClass=groupOfNames)" \
    cn description

if [ $? -eq 0 ]; then
    echo "Group listing completed successfully."
else
    echo "ERROR: List operation failed. Check the LDAP server logs for details."
fi