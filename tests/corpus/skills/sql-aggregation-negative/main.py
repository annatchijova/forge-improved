def load_records(conn, ids):
    return conn.execute("SELECT * FROM records WHERE id IN (?)", (ids,))
