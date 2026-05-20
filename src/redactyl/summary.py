from collections import Counter

from redactyl.models import ScanResult


def summarize_result(result: ScanResult) -> dict:
    counter = Counter(f.type for f in result.findings)
    return {
        "source": result.source,
        "text_length": result.text_length,
        "total_findings": len(result.findings),
        "by_type": dict(counter),
    }


def summarize_results(results: list[ScanResult]) -> dict:
    counter = Counter()
    for result in results:
        for finding in result.findings:
            counter[finding.type] += 1

    return {
        "files_scanned": len(results),
        "total_findings": sum(len(r.findings) for r in results),
        "by_type": dict(counter),
    }