from dotenv import load_dotenv
import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import random
import string
import secrets
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Authentication API", version="2.0.0")


from fastapi.middleware.cors import CORSMiddleware

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Load environment variables before using them
load_dotenv()

# ============= CONFIGURATION =============
DATABASE_URL = os.getenv("DATABASE_URL")
GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OTP_EXPIRY_MINUTES = 5
OTP_LENGTH = 6
RESET_TOKEN_EXPIRE_HOURS = 1

# ============= DATABASE SETUP =============
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(Text, nullable=True)
    full_name = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=False)  
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)
    last_login = Column(DateTime, nullable=True)

class OTP(Base):
    __tablename__ = "otps"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    otp = Column(String(10), nullable=False)
    expiry_time = Column(DateTime, nullable=False)
    is_verified = Column(Boolean, default=False)
    otp_type = Column(String(20), default="login")  # Added: 'signup', 'login', 'reset'
    created_at = Column(DateTime, default=datetime.now)

class ResetToken(Base):
    __tablename__ = "reset_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(Text, nullable=False, unique=True)
    expiry_time = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)

from sqlalchemy import (
    Column, Integer, String, ForeignKey, Text, Boolean, DateTime, Float
)
from sqlalchemy.orm import relationship

class ShoppingHistory(Base):
    __tablename__ = "shopping_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(Text, nullable=False, unique=True)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)

    product_name = Column(String(255), nullable=False)
    category = Column(String(100), nullable=True)
    quantity = Column(Integer, default=1)
    price_per_unit = Column(Float, nullable=False)
    total_price = Column(Float, nullable=False)
    payment_method = Column(String(50), nullable=True)  
    status = Column(String(50), default="completed")    
    delivery_address = Column(Text, nullable=True)
    delivery_date = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


Base.metadata.create_all(bind=engine)

# ============= UTILITIES =============
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def generate_otp() -> str:
    return ''.join(random.choices(string.digits, k=OTP_LENGTH))

def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)

def send_email(recipient: str, subject: str, body: str) -> bool:
    try:
        message = MIMEText(body)
        message["Subject"] = subject
        message["From"] = GMAIL_USER
        message["To"] = recipient
        
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, recipient, message.as_string())
        return True
    except Exception as e:
        print(f"❌ Email sending failed: {e}")
        return False

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload

# ============= PYDANTIC MODELS =============
class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class VerifySignupRequest(BaseModel):
    email: EmailStr
    otp: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class OTPRequest(BaseModel):
    email: EmailStr

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    reset_token: str
    new_password: str

# ============= FASTAPI APP =============

@app.get("/")
def root():
    return {"message": "Authentication API with Email Verification", "docs": "/docs"}

@app.get("/shopping-history")
def get_all_shopping_history(db: Session = Depends(get_db)):
    shopping_history = db.query(ShoppingHistory).all()
    return shopping_history
# ============= SIGNUP (STEP 1: Send OTP) =============
@app.post("/api/auth/signup")
def signup(request: SignupRequest, db: Session = Depends(get_db)):
    """
    Step 1: Create user and send verification OTP
    User account remains inactive until OTP is verified
    """
    # Check if user exists
    existing_user = db.query(User).filter(User.email == request.email).first()
    
    if existing_user:
        if existing_user.is_verified:
            raise HTTPException(status_code=400, detail="Email already registered and verified")
        else:
            # User exists but not verified - allow resending OTP
            user = existing_user
            user.password = hash_password(request.password)
            user.full_name = request.full_name
    else:
        # Create new user (inactive)
        user = User(
            email=request.email,
            password=hash_password(request.password),
            full_name=request.full_name,
            is_active=False,
            is_verified=False,
            created_at=datetime.now()
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    
    # Generate OTP
    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    
    # Save OTP
    new_otp = OTP(
        user_id=user.id, 
        otp=otp, 
        expiry_time=expiry, 
        is_verified=False,
        otp_type="signup",
        created_at=datetime.now()
    )
    db.add(new_otp)
    db.commit()
    
    # Send verification email
    body = f"""Welcome to Our Platform!

Your verification code is: {otp}

This code will expire in {OTP_EXPIRY_MINUTES} minutes.

Please verify your email to complete registration.

If you didn't create this account, please ignore this email."""
    
    email_sent = send_email(request.email, "Verify Your Email - OTP Code", body)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send verification email. Please try again.")
    
    return {
        "success": True,
        "message": f"Verification code sent to {request.email}. Please check your email.",
        "email": request.email,
        "requires_verification": True
    }

# ============= VERIFY SIGNUP OTP (STEP 2) =============
@app.post("/api/auth/verify-signup")
def verify_signup(request: VerifySignupRequest, db: Session = Depends(get_db)):
    """
    Step 2: Verify OTP and activate user account
    """
    # Get user
    user = db.query(User).filter(User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified. Please login.")
    
    # Get latest signup OTP
    otp = db.query(OTP).filter(
        OTP.user_id == user.id,
        OTP.otp_type == "signup"
    ).order_by(OTP.created_at.desc()).first()
    
    if not otp:
        raise HTTPException(status_code=404, detail="No verification code found. Please request a new one.")
    
    if datetime.now() > otp.expiry_time:
        raise HTTPException(status_code=400, detail="Verification code expired. Please request a new one.")
    
    if otp.is_verified:
        raise HTTPException(status_code=400, detail="Code already used. Please request a new one.")
    
    if otp.otp != request.otp:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    
    # Activate user
    otp.is_verified = True
    user.is_verified = True
    user.is_active = True
    user.last_login = datetime.now()
    db.commit()
    
    # Generate access token
    access_token = create_access_token({"user_id": user.id, "email": user.email})
    
    return {
        "success": True,
        "message": "Email verified successfully! Registration complete.",
        "access_token": access_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_verified": user.is_verified
        }
    }

# ============= RESEND VERIFICATION CODE =============
@app.post("/api/auth/resend-verification")
def resend_verification(request: OTPRequest, db: Session = Depends(get_db)):
    """
    Resend verification OTP for unverified accounts
    """
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.is_verified:
        raise HTTPException(status_code=400, detail="Email already verified. Please login.")
    
    # Generate new OTP
    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    
    new_otp = OTP(
        user_id=user.id,
        otp=otp,
        expiry_time=expiry,
        is_verified=False,
        otp_type="signup",
        created_at=datetime.now()
    )
    db.add(new_otp)
    db.commit()
    
    # Send email
    body = f"""Your new verification code is: {otp}

This code will expire in {OTP_EXPIRY_MINUTES} minutes.

If you didn't request this, please ignore this email."""
    
    email_sent = send_email(request.email, "New Verification Code", body)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send email")
    
    return {
        "success": True,
        "message": "New verification code sent to your email"
    }

# ============= LOGIN =============
@app.post("/api/auth/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Login with email and password (only for verified users)
    """
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user or not user.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.is_verified:
        raise HTTPException(
            status_code=403, 
            detail="Email not verified. Please verify your email first."
        )
    
    if not verify_password(request.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account is deactivated")
    
    # Update last login
    user.last_login = datetime.now()
    db.commit()
    
    # Generate token
    access_token = create_access_token({"user_id": user.id, "email": user.email})
    
    return {
        "success": True,
        "message": "Login successful",
        "access_token": access_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name
        }
    }

# ============= SEND OTP (for OTP-based login) =============
@app.post("/api/auth/send-otp")
def send_otp(request: OTPRequest, db: Session = Depends(get_db)):
    """
    Send OTP for passwordless login (only for verified users)
    """
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found. Please signup first.")
    
    if not user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please complete signup verification first."
        )
    
    # Generate OTP
    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    
    new_otp = OTP(
        user_id=user.id,
        otp=otp,
        expiry_time=expiry,
        is_verified=False,
        otp_type="login",
        created_at=datetime.now()
    )
    db.add(new_otp)
    db.commit()
    
    # Send email
    body = f"""Your login OTP code is: {otp}

This code will expire in {OTP_EXPIRY_MINUTES} minutes.

If you didn't request this, please ignore this email."""
    
    email_sent = send_email(request.email, "Your Login OTP Code", body)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send OTP")
    
    return {
        "success": True,
        "message": "OTP sent successfully to your email"
    }

# ============= VERIFY OTP (for OTP-based login) =============
@app.post("/api/auth/verify-otp")
def verify_otp(request: VerifyOTPRequest, db: Session = Depends(get_db)):
    """
    Verify OTP for passwordless login
    """
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")
    
    # Get latest login OTP
    otp = db.query(OTP).filter(
        OTP.user_id == user.id,
        OTP.otp_type == "login"
    ).order_by(OTP.created_at.desc()).first()
    
    if not otp:
        raise HTTPException(status_code=404, detail="No OTP found. Please request a new OTP")
    
    if datetime.now() > otp.expiry_time:
        raise HTTPException(status_code=400, detail="OTP expired. Please request a new OTP")
    
    if otp.is_verified:
        raise HTTPException(status_code=400, detail="OTP already used. Please request a new OTP")
    
    if otp.otp != request.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    # Mark as verified
    otp.is_verified = True
    user.last_login = datetime.now()
    db.commit()
    
    # Generate token
    access_token = create_access_token({"user_id": user.id, "email": user.email})
    
    return {
        "success": True,
        "message": "Login successful",
        "access_token": access_token,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name
        }
    }

# ============= FORGOT PASSWORD =============
@app.post("/api/auth/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        return {
            "success": True,
            "message": "If email exists, password reset instructions have been sent"
        }
    
    # Generate reset token
    reset_token = generate_reset_token()
    expiry = datetime.now() + timedelta(hours=RESET_TOKEN_EXPIRE_HOURS)
    
    new_token = ResetToken(
        user_id=user.id,
        token=reset_token,
        expiry_time=expiry,
        is_used=False,
        created_at=datetime.now()
    )
    db.add(new_token)
    db.commit()
    
    # Send email
    body = f"""Password Reset Request

Your password reset token: {reset_token}

This token will expire in {RESET_TOKEN_EXPIRE_HOURS} hour(s).

Use this token with the reset-password API endpoint.

If you didn't request this, please ignore this email."""
    
    send_email(request.email, "Password Reset Request", body)
    
    return {
        "success": True,
        "message": "Password reset instructions sent to your email"
    }

# ============= RESET PASSWORD =============
@app.post("/api/auth/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    
    token = db.query(ResetToken).filter(
        ResetToken.user_id == user.id,
        ResetToken.token == request.reset_token
    ).order_by(ResetToken.created_at.desc()).first()
    
    if not token:
        raise HTTPException(status_code=400, detail="Invalid reset token")
    
    if datetime.now() > token.expiry_time:
        raise HTTPException(status_code=400, detail="Reset token has expired")
    
    if token.is_used:
        raise HTTPException(status_code=400, detail="Reset token already used")
    
    # Update password
    user.password = hash_password(request.new_password)
    token.is_used = True
    db.commit()
    
    return {
        "success": True,
        "message": "Password reset successful"
    }

# ============= GET PROFILE (PROTECTED) =============
@app.get("/api/user/profile")
def get_profile(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "created_at": str(user.created_at),
        "last_login": str(user.last_login) if user.last_login else None
    }

# ============= VERIFY TOKEN =============
@app.get("/api/user/verify-token")
def verify_token_endpoint(current_user: dict = Depends(get_current_user)):
    return {
        "success": True,
        "message": "Token is valid",
        "user_id": current_user["user_id"],
        "email": current_user["email"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)