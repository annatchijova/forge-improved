import numpy as np


def estimate_distance(samples, sample_rate):
    peak_index = np.argmax(samples)
    time_s = peak_index / sample_rate
    return float(time_s * 343.0)
