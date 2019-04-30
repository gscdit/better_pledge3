import json

with open('/etc/betterpledge_config.json') as config_file:
    config = json.load(config_file)


class Config():
    SECRET_KEY = config.get('SECRET_KEY') or 'secretkey'
    SQLALCHEMY_DATABASE_URI = config.get(
        'SQLALCHEMY_DATABASE_URI') or 'sqlite:///app.db'
    FLASK_ADMIN_SWATCH = 'cerulean'
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:rootroot@localhost:3307/db_test'
    SENDGRID_API_KEY = config.get('SENDGRID_API_KEY') or 'your_api_key'
    SENDGRID_DEFAULT_FROM = config.get(
        'SENDGRID_DEFAULT_FROM') or 'marketing@gscditu.com'
