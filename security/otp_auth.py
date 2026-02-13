import random

def generate_otp():
    return str(random.randint(100000, 999999))

def verify_otp(real_otp, user_otp):
    return real_otp == user_otp
