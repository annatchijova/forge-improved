def replace_records(conn, row):
    conn.execute("INSERT INTO records VALUES (?)", (row,))
    conn.execute("DELETE FROM records WHERE stale = 1")
