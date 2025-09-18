# Test authentication
from app import PasswordManager

TEST_DB = "test_users.db"

# Initialise password manager
pm = PasswordManager(TEST_DB)

# Authentication with user that does not exist
print("RED TEST: USER DOES NOT EXIST")
assert pm.verify_user("Alice", "secret") == False

# Create user 
print("Creating user: ")
api_key = pm.register_user("Alice", "secret", "patient")

print("GREEN TEST: User exists")
assert pm.verify_user("Alice", "secret") == True

print("All tests passed! ")
