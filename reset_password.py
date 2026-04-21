print("Script is running...")

from passlib.context import CryptContext

# Create bcrypt context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Set new password
new_password = "admin123"

# Generate hash
hashed_password = pwd_context.hash(new_password)

# Print result
print("New hashed password:")
print(hashed_password)