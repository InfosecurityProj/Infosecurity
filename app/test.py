# Import the SQLAlchemy engine
from sqlalchemy import create_engine

# Create a connection to the database
engine = create_engine("sqlite:///test1.db")

# Create a query
query = "SELECT * FROM user"

# Execute the query
results = engine.execute(query)

# Print the results
for x in results.fetchall():
    print(f"Role:{x[3]} User:{x[1]} ID:{x[0]}")