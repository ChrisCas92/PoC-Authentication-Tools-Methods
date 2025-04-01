#!/bin/bash
# This script searches for a user by sAMAccountName
# It demonstrates how to find Windows users by their login name

if [ -z "$1" ]; then
    echo "Usage: $0 <sAMAccountName>"
    echo "Example: $0 jdoe"
    exit 1
fi

USERNAME=$1
echo "Searching for user with sAMAccountName=$USERNAME..."

docker exec openldap ldapsearch -H ldap://localhost:389 -x \
    -D "cn=ServiceAccount,ou=Users,dc=example,dc=com" \
    -w servicepassword \
    -b "dc=example,dc=com" \
    "(sAMAccountName=$USERNAME)"

if [ $? -eq 0 ]; then
    echo "Search operation completed successfully."
else
    echo "ERROR: Search operation failed. Check the LDAP server logs for details."
fi