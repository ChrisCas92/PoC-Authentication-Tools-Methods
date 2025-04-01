#!/bin/bash
# This script tests authentication with the service account
# It attempts to bind with the service account credentials and perform a simple search

echo "Testing authentication with Service Account..."
docker exec openldap ldapsearch -H ldap://localhost:389 -x \
    -D "cn=ServiceAccount,ou=Users,dc=example,dc=com" \
    -w servicepassword \
    -b "dc=example,dc=com" -s base

if [ $? -eq 0 ]; then
    echo "SUCCESS: Authentication with Service Account successful!"
else
    echo "ERROR: Authentication failed. Check service account credentials and permissions."
    echo "Run 'docker-compose logs openldap' to see LDAP server logs for more details."
fi