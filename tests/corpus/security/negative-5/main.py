from fastapi import Depends, FastAPI

app = FastAPI()


def require_admin():
    return "admin"


# Guarded by a real auth dependency.
@app.post("/webhooks/admin-replay")
def admin_replay(payload, _: str = Depends(require_admin)):
    connection.execute("UPDATE orders SET status=? WHERE id=?", (payload.status, payload.order_id))
    return {"ok": True}


# No Depends(), but verifies a provider signature in the body.
@app.post("/webhooks/payment")
def payment_webhook(payload, request):
    signature = request.headers.get("X-Signature")
    if not hmac.compare_digest(signature, expected_signature(payload)):
        raise PermissionError("bad signature")
    connection.execute("UPDATE orders SET status=? WHERE id=?", (payload.status, payload.order_id))
    return {"ok": True}


# Intentionally public route (not named like a webhook) - checkout must
# remain unauthenticated by this project's own design.
@app.post("/checkout")
def checkout(payload):
    connection.execute("INSERT INTO orders(status) VALUES('pending_payment')")
    return {"ok": True}
