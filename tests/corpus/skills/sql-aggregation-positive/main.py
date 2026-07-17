def load_records(conn, ids):
    for item_id in ids:
        conn.execute("SELECT * FROM records WHERE id = ?", (item_id,))
