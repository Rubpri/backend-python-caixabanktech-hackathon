class Config:    
    DEBUG = True  
    SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:root@mysql:3306/bankingapp"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = "jwt_secret_key"  
    JWT_ACCESS_TOKEN_EXPIRES = 3600  