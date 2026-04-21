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

# ---------------- DATABASE ----------------
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# ---------------- APP ----------------
app = FastAPI(title="AI Fraud Detection API")

# ---------------- SECURITY ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ---------------- ML MODEL ----------------
try:
    model = joblib.load("fraud_model.pkl")
    print("ML Model Loaded")
except:
    model = None
    print("Model not loaded")

# ---------------- DB SESSION ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------- JWT ----------------
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------------- EMAIL ----------------
def send_email(to_email, subject, body):
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
    except Exception as e:
        print("Email error:", e)

# ---------------- REGISTER ----------------
@app.post("/register/")
def register(username: str, password: str, db: Session = Depends(get_db)):
    try:
        user = db.execute(
            text("SELECT * FROM users WHERE username=:u"),
            {"u": username}
        ).fetchone()

        if user:
            raise HTTPException(status_code=400, detail="Username already exists")

        hashed_password = pwd_context.hash(password)

        db.execute(
            text("INSERT INTO users (username, password) VALUES (:u, :p)"),
            {"u": username, "p": hashed_password}
        )

        db.commit()
        return {"message": "User registered successfully"}

    except Exception as e:
        db.rollback()
        print("Register error:", e)
        raise HTTPException(status_code=500, detail="Registration failed")

# ---------------- LOGIN ----------------
@app.post("/login/")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.execute(
        text("SELECT * FROM users WHERE username=:u"),
        {"u": username}
    ).fetchone()

    if not user or not pwd_context.verify(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": username})
    return {"access_token": token}

# ---------------- ACCOUNT ----------------
@app.post("/account/")
def create_account(email: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    db.execute(
        text("INSERT INTO accounts (email, status) VALUES (:e, 'active')"),
        {"e": email}
    )
    db.commit()
    return {"message": "Account created"}

# ---------------- TRANSACTION ----------------
@app.post("/transaction/")
def transaction(account_id: int, amount: float, background_tasks: BackgroundTasks,
                db: Session = Depends(get_db), user=Depends(get_current_user)):

    acc = db.execute(
        text("SELECT * FROM accounts WHERE account_id=:id"),
        {"id": account_id}
    ).fetchone()

    if not acc:
        raise HTTPException(status_code=404, detail="Account not found")

    if acc.status == "blocked":
        raise HTTPException(status_code=403, detail="Account blocked")

    if not model:
        raise HTTPException(status_code=500, detail="Model not loaded")

    input_data = np.zeros((1, 30))
    input_data[0][-1] = amount

    risk_score = float(model.predict_proba(input_data)[0][1])

    status = "approved"
    if risk_score > FRAUD_THRESHOLD:
        status = "blocked"
        db.execute(
            text("UPDATE accounts SET status='blocked' WHERE account_id=:id"),
            {"id": account_id}
        )

    db.execute(
        text("""
        INSERT INTO transactions (account_id, amount, risk_score, status)
        VALUES (:a, :m, :r, :s)
        """),
        {"a": account_id, "m": amount, "r": risk_score, "s": status}
    )

    db.commit()

    # Email user
    if acc.email:
        background_tasks.add_task(
            send_email,
            acc.email,
            "Transaction Alert",
            f"Amount: {amount}\nRisk: {risk_score}\nStatus: {status}"
        )

    # Email admin
    if status == "blocked" and ADMIN_EMAIL:
        background_tasks.add_task(
            send_email,
            ADMIN_EMAIL,
            "Fraud Alert",
            f"Account {account_id} blocked\nRisk: {risk_score}"
        )

    return {
        "account_id": account_id,
        "amount": amount,
        "risk_score": risk_score,
        "status": status
    }