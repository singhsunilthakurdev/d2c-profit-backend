from fastapi import FastAPI, Request
import stripe
import psycopg2
import os

app = FastAPI()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")


# -----------------------------------
# Database Connection (SSL Required)
# -----------------------------------
def get_connection():
    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require"
    )


# -----------------------------------
# Stripe Webhook
# -----------------------------------
@app.post("/webhook")
async def stripe_webhook(request: Request):

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, WEBHOOK_SECRET
        )
    except Exception as e:
        return {"error": f"Webhook error: {str(e)}"}

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]

        email = session["customer_details"]["email"]
        customer_id = session["customer"]
        subscription_id = session.get("subscription")

        try:
            conn = get_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO users (email, stripe_customer_id, stripe_subscription_id, subscription_status)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (email)
                DO UPDATE SET
                    stripe_customer_id = EXCLUDED.stripe_customer_id,
                    stripe_subscription_id = EXCLUDED.stripe_subscription_id,
                    subscription_status = 'active'
            """, (email, customer_id, subscription_id, "active"))

            conn.commit()
            cur.close()
            conn.close()

        except Exception as db_error:
            return {"error": f"Database error: {str(db_error)}"}

    return {"status": "success"}


# -----------------------------------
# Verify User Access
# -----------------------------------
@app.get("/verify")
def verify_user(email: str):

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            "SELECT subscription_status FROM users WHERE email=%s",
            (email,)
        )

        result = cur.fetchone()

        cur.close()
        conn.close()

        if result and result[0] == "active":
            return {"access": True}

        return {"access": False}

    except Exception as e:
        return {"error": f"Verify error: {str(e)}"}
