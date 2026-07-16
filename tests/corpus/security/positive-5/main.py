from fastapi import FastAPI

app = FastAPI()


@app.post("/webhooks/payment")
def payment_webhook(payload):
    status = payload.status
    order_id = payload.order_id
    connection.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    return {"order_id": order_id, "status": status}
