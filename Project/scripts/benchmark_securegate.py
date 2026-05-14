import argparse
import csv
import statistics
import time
from pathlib import Path

from securegate.prompt_defense import PromptDefenseEngine
from securegate.response_sanitizer import ResponseSanitizationEngine


def run_benchmark(data_dir: Path) -> None:
    prompt_engine = PromptDefenseEngine()
    response_engine = ResponseSanitizationEngine()

    prompt_file = data_dir / "prompt_injection_samples.csv"
    leak_file = data_dir / "sensitive_leak_samples.csv"

    prompt_latencies = []
    leak_latencies = []
    prompt_rows = 0
    leak_rows = 0

    with prompt_file.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            started = time.perf_counter()
            prompt_engine.inspect(row["text"])
            prompt_latencies.append((time.perf_counter() - started) * 1000)
            prompt_rows += 1

    with leak_file.open("r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            started = time.perf_counter()
            response_engine.sanitize(row["text"])
            leak_latencies.append((time.perf_counter() - started) * 1000)
            leak_rows += 1

    print("SecureGate benchmark results")
    print(f"Prompt samples: {prompt_rows}")
    print(f"Leak samples: {leak_rows}")
    print(f"Prompt mean latency (ms): {statistics.mean(prompt_latencies):.3f}")
    print(f"Prompt p95 latency (ms): {statistics.quantiles(prompt_latencies, n=20)[18]:.3f}")
    print(f"Leak mean latency (ms): {statistics.mean(leak_latencies):.3f}")
    print(f"Leak p95 latency (ms): {statistics.quantiles(leak_latencies, n=20)[18]:.3f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SecureGate benchmark on sample datasets.")
    parser.add_argument("--data-dir", default="data", help="Directory containing evaluation CSV files.")
    args = parser.parse_args()
    run_benchmark(Path(args.data_dir))


if __name__ == "__main__":
    main()
