import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///voting.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # OTP Configuration (No Twilio needed)
    OTP_EXPIRATION = 300  # 5 minutes in seconds