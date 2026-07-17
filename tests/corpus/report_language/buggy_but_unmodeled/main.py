"""Realistic logic defects deliberately outside FORGE's current detector scope."""
import json


def parse_controlled_input(raw):
    if not raw:
        raise ValueError("payload required")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid payload") from exc


def lookup(items, index, optional):
    return items[index] if optional is None else optional.name


def ship(order):
    order["state"] = "shipped"
    return order


counter = 0


def increment():
    global counter
    counter += 1


def get_invoice(store, invoice_id):
    return store[invoice_id]


def persist(client, record):
    client.save(record)
    return "ok"


def increment_text(value):
    return value + "1"
