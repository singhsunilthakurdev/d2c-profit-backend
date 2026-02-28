from fastapi import FastAPI, Request
from pydantic import BaseModel
import stripe
import psycopg2
import os
import bcrypt

app = FastAPI()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")

DOMAIN = "http://localhost:8501"  # change to your domain later


def get_connection():
    return psycopg2.connect(DATABASE_URL)


# -------------------------
# MODELS
# -------------------------
class AuthData(BaseModel):
    email: str
    password: str


# -------------------------
# REGISTER
# -------------------------
@app.post("/register")
def register(data: AuthData):
    hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt())

    conn = get_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            INSERT INTO users (email, password)
            VALUES (%s, %s)
        """, (data.email, hashed.decode()))

        conn.commit()
        return {"registered": True}
    except:
        return {"error": "User already exists"}
    finally:
        cur.close()
        conn.close()


# -------------------------
# LOGIN
# -------------------------
@app.post("/login")
def login(data: AuthData):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT password, subscription_status FROM users WHERE email=%s", (data.email,))
    result = cur.fetchone()

    cur.close()
    conn.close()

    if not result:
        return {"login": False}

    stored_password, subscription = result

    if bcrypt.checkpw(data.password.encode(), stored_password.encode()):
        return {"login": True, "subscription": subscription}

    return {"login": False}


# -------------------------
# CREATE CHECKOUT SESSION
# -------------------------
@app.post("/create-checkout-session")
def create_checkout_session(data: AuthData):

    session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        mode="subscription",
        line_items=[{
            "price": "YOUR_PRICE_ID",  # replace from Stripe
            "quantity": 1
        }],
        customer_email=data.email,
        success_url=f"{DOMAIN}?success=true",
        cancel_url=f"{DOMAIN}?canceled=true",
    )

    return {"checkout_url": session.url}


# -------------------------
# STRIPE WEBHOOK
# -------------------------
@app.post("/webhook")
async def stripe_webhook(request: Request):

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, WEBHOOK_SECRET
        )
    except Exception:
        return {"error": "Invalid webhook"}

    if event["type"] == "checkout.session.completed":

        session = event["data"]["object"]
        email = session["customer_email"]

        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            UPDATE users
            SET subscription_status='active'
            WHERE email=%s
        """, (email,))

        conn.commit()
        cur.close()
        conn.close()

    return {"status": "ok"}
