from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import joblib
import numpy as np
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText

# ---------------- LOAD ENV ----------------
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
FRAUD_THRESHOLD = float(os.getenv("FRAUD_THRESHOLD", 0.8))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# -------- DEBUG PRINTS (CHECK IF ENV LOADED) --------
print("DATABASE_URL:", DATABASE_URL)
print("SMTP_SERVER:", SMTP_SERVER)
print("EMAIL_USER:", EMAIL_USER)

# ---------------- DATABASE ----------------
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# ---------------- APP ----------------
app = FastAPI(title="AI-Powered Fraud Detection API")

# ---------------- SECURITY ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ---------------- LOAD ML MODEL ----------------
try:
    model = joblib.load("fraud_model.pkl")
    print("✅ ML Model Loaded Successfully")
except Exception as e:
    print("❌ Failed to load ML model:", e)
    model = None

# ---------------- DB DEPENDENCY ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------- JWT FUNCTIONS ----------------
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ---------------- EMAIL FUNCTION ----------------
def send_email(to_email: str, subject: str, body: str):
    if not SMTP_SERVER or not EMAIL_USER or not EMAIL_PASSWORD:
        print("⚠ Email settings not configured properly.")
        return

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = to_email

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()

        print("✅ Email sent successfully")

    except Exception as e:
        print("❌ Email failed:", e)

# ---------------- REGISTER ----------------
@app.post("/register/")
def register(username: str, password: str, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(password)

    try:
        db.execute(
            text("INSERT INTO users (username, password) VALUES (:u, :p)"),
            {"u": username, "p": hashed_password}
        )
        db.commit()
    except:
        raise HTTPException(status_code=400, detail="Username already exists")

    return {"message": "User registered successfully"}

# ---------------- LOGIN ----------------
@app.post("/login/")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.execute(
        text("SELECT * FROM users WHERE username=:u"),
        {"u": username}
    ).fetchone()

    if not user or not pwd_context.verify(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token({"sub": username})
    return {"access_token": access_token}

# ---------------- CREATE ACCOUNT ----------------
@app.post("/account/")
def create_account(
    email: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    db.execute(
        text("""
        INSERT INTO accounts (email, status)
        VALUES (:email, 'active')
        """),
        {"email": email}
    )
    db.commit()

    return {"message": "Account created successfully"}

# ---------------- TRANSACTION ROUTE ----------------
@app.post("/transaction/")
def create_transaction(
    account_id: int,
    amount: float,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    account = db.execute(
        text("SELECT * FROM accounts WHERE account_id=:id"),
        {"id": account_id}
    ).fetchone()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    if account.status == "blocked":
        raise HTTPException(status_code=403, detail="This account is blocked")

    if not model:
        raise HTTPException(status_code=500, detail="ML model not loaded")

    # ---- ML INPUT (30 features)
    input_data = np.zeros((1, 30))
    input_data[0][-1] = amount

    probability = model.predict_proba(input_data)[0][1]
    risk_score = round(float(probability), 4)

    transaction_status = "approved"

    if risk_score > FRAUD_THRESHOLD:
        transaction_status = "blocked"
        db.execute(
            text("UPDATE accounts SET status='blocked' WHERE account_id=:id"),
            {"id": account_id}
        )

    # ---- SAVE TRANSACTION
    db.execute(
        text("""
        INSERT INTO transactions (account_id, amount, risk_score, status)
        VALUES (:account_id, :amount, :risk_score, :status)
        """),
        {
            "account_id": account_id,
            "amount": amount,
            "risk_score": risk_score,
            "status": transaction_status
        }
    )

    db.commit()

    # ---- EMAIL USER
    if account.email:
        subject = f"Transaction Alert - Account #{account_id}"
        body = f"""
Transaction Alert

Account ID: {account_id}
Amount: {amount}
Risk Score: {risk_score}
Status: {transaction_status}
Time: {datetime.utcnow()}
"""
        background_tasks.add_task(send_email, account.email, subject, body)

    # ---- EMAIL ADMIN
    if transaction_status == "blocked" and ADMIN_EMAIL:
        background_tasks.add_task(
            send_email,
            ADMIN_EMAIL,
            "🚨 Fraud Alert Detected",
            f"Fraud detected on Account {account_id}\nRisk Score: {risk_score}"
        )

    return {
        "account_id": account_id,
        "amount": amount,
        "risk_score": risk_score,
        "transaction_status": transaction_status
    }