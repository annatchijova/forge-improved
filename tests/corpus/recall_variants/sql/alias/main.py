def find(cur, user):
    query = "SELECT * FROM users WHERE name = '" + user
    return cur.execute(query)
