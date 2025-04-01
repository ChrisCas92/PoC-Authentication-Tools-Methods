#!/bin/bash
# This comprehensive script tests the LDAP server configuration
# It runs a series of tests to verify connectivity, authentication, and data

echo "==============================================="
echo "Starting comprehensive LDAP environment testing"
echo "==============================================="
echo

echo "Test 1: Basic connectivity"
echo "-------------------------"
./test-connection.sh
echo

echo "Test 2: Service account authentication"
echo "------------------------------------"
./test-auth.sh
echo

echo "Test 3: Finding user 'jdoe'"
echo "-------------------------"
./find-user.sh jdoe
echo

echo "Test 4: Finding group 'Developers'"
echo "-------------------------------"
./find-group.sh Developers
echo

echo "Test 5: Listing all users"
echo "----------------------"
./list-users.sh
echo

echo "Test 6: Listing all groups"
echo "-----------------------"
./list-groups.sh
echo

echo "==============================================="
echo "LDAP environment testing completed"
echo "==============================================="