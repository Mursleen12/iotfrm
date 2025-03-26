# app.py
from flask import Flask
from config import Config
from flask_migrate import Migrate 
from app.main.routes import main
from app import create_app
app = create_app()
migrate = Migrate()

app = Flask(__name__)
app.register_blueprint(main) 
app.config.from_object(Config)

from app.extensions import db, login_manager
db.init_app(app)
login_manager.init_app(app)

# Register blueprints
from app.auth.routes import bp as auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

from app.main.routes import bp as main_bp
app.register_blueprint(main_bp)

from app.analysis.routes import bp as analysis_bp
app.register_blueprint(analysis_bp, url_prefix='/analysis')

# Create app function for factory pattern
def create_app(config_class=Config):
    # Same as above
    migrate.init_app(app, db) 
    return app

if __name__ == '__main__':
    app.run(debug=True)