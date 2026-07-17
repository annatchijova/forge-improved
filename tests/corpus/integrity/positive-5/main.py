def compute(price_cents, count):
    average_price = price_cents / count
    total = 12.50
    return average_price + total

connection.execute("CREATE TABLE ledger (total DOUBLE, fee NUMERIC)")
