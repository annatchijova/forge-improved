import pickle


def persist(handle, payload):
    pickle.dump(payload, handle)
