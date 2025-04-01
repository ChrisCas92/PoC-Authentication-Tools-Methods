## Testing Scripts

The `scripts` directory contains several bash scripts to help you test and verify your LDAP environment:

### Basic Tests

- `test-connection.sh`: Tests basic connectivity to the LDAP server
- `test-auth.sh`: Tests authentication with the service account
- `test-ldap.sh`: Runs a comprehensive series of tests to verify the environment

### Data Queries

- `find-user.sh <username>`: Finds a user by sAMAccountName (e.g., `./find-user.sh jdoe`)
- `find-group.sh <groupname>`: Finds a group and lists its members (e.g., `./find-group.sh Developers`)
- `list-users.sh`: Lists all users in the directory
- `list-groups.sh`: Lists all groups in the directory

To use these scripts:

```bash
cd ldap-test/scripts
./test-ldap.sh  # Run all tests
./find-user.sh jdoe  # Find a specific user
```
