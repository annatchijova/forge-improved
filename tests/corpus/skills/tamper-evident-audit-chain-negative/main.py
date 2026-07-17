def append_audit(ledger, entry, previous_hash):
    entry["prev_hash"] = previous_hash
    ledger.append(entry)
