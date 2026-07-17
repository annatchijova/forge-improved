def find(cur, user):
    return cur.execute("SELECT * FROM users WHERE name = '%s'" % user)
