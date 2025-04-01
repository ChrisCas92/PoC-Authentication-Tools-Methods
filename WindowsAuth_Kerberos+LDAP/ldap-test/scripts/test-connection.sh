#!/bin/bash
# This script tests basic connectivity to the LDAP server
# It performs a simple anonymous bind and retrieves the base entry

echo "Testing basic connection to OpenLDAP server..."
docker exec openldap ldapsearch -H ldap://localhost:389 -x -b "dc=example,dc=com" -s base

if [ $? -eq 0 ]; then
    echo "SUCCESS: Basic connection to LDAP server established!"
else
    echo "ERROR: Could not connect to LDAP server. Check if the container is running."
    echo "Run 'docker-compose ps' to check container status."
fi