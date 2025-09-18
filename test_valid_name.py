from app import PasswordManager, is_valid_name_input

DB = "test_valid_name.db"
pm = PasswordManager(DB)

#RED TEST
print("Test 1: authentication on non existing user")
assert pm.verify_user("Alice", "password") == False

print("Create user")
pm.register_user("Alice", "password", "patient")

print("Test 2: authentication on existing user")
assert pm.verify_user("Alice", "password") == True  

#Test 2: Validating name
print("Test 3: non legal name: ")
assert is_valid_name_input("ola nordmann") == False

print("Test 4: non legal name with special characters: ")
assert is_valid_name_input("O<a N>rdmann") == False

print("Test 5: legal name: ")
assert is_valid_name_input("Ola Nordmann") == True

print("All tests passed!")