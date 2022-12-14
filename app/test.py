# # Import the SQLAlchemy engine
# from sqlalchemy import create_engine

# # Create a connection to the database
# engine = create_engine("sqlite:///test1.db")

# # Create a query
# query = "SELECT * FROM user"

# # Execute the query
# results = engine.execute(query)

# # Print the results
# for x in results.fetchall():
#     print(f"Role:{x[3]} User:{x[1]} ID:{x[0]}")
import hashlib
salt = bytes("1" + "admin", "utf-8")
print(salt,"password salt")
password="asd"
hashed_password = hashlib.pbkdf2_hmac(
    "sha256",  # The hashing algorithm to use
    password.encode(),  # The password to hash, as bytes
    salt,  # The salt to use, as bytes
    100000  # The number of iterations to use
)
print(hashed_password,"pw hash")