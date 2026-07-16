import json


def collect_metrics(root):
    # The version key lives in this literal, in a different file than
    # whoever eventually serializes the returned dict.
    return {"metrics_schema_version": "1.0", "root": str(root)}


def validate_independent_results(results):
    return {"independence_schema_version": "1.0", "status": "INDEPENDENCE_VERIFIED"}


def load_and_validate(directory):
    # Transitive: this returns another producer's already-versioned dict,
    # one more call away than collect_metrics above.
    return validate_independent_results({})


def write_metrics(root, destination):
    metrics = collect_metrics(root)
    destination.write_text(json.dumps(metrics, indent=2))


def write_validation_artifact(directory, destination):
    summary = load_and_validate(directory)
    destination.write_text(json.dumps(summary, indent=2))
