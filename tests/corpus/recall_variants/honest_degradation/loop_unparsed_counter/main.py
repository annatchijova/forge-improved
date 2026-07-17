def analyze_directory(records):
    findings = []
    unparsed = 0
    for record in records:
        try:
            findings.append(parse_record(record))
        except ValueError:
            unparsed += 1
            continue
    return {"findings": findings, "unparsed_files": unparsed}
