def execute(obj, user_input):
    return getattr(obj, "eval")(user_input)
