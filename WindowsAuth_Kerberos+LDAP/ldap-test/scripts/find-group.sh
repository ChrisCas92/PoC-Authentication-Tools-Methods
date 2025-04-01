#!/bin/bash
# This script searches for a group and lists its members
# It demonstrates how to find group memberships, which is useful for role-based access control

if [ -z "$1" ]; then
    echo "Usage: $0 <groupName>"
    echo "Example: $0 Developers"
    exit 1
fi

GROUPNAME=$1
echo "Searching for group $GROUPNAME and its members..."

docker exec openldap ldapsearch -H ldap://localhost:389 -x \
    -D "cn=ServiceAccount,ou=Users,dc=example,dc=com" \
    -w servicepassword \
    -b "dc=example,dc=com" \
    "(cn=$GROUPNAME)" cn description member

if [ $? -eq 0 ]; then
    echo "Search operation completed successfully."
else
    echo "ERROR: Search operation failed. Check the LDAP server logs for details."
fi