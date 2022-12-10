from app.routes import app
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy(app)

if __name__ == '__main__':
    migrate = Migrate(app, db)
    
    app.run(port="3000",debug=True)