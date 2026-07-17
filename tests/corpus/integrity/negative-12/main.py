from decimal import Decimal

def compute():
    total = Decimal("12.50")
    return total

connection.execute("CREATE TABLE ledger (total DECIMAL)")
