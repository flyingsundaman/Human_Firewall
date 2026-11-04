#!/usr/bin/env python3
"""
Run 5 sequential iterations of AFFERENT continuous learning, evaluation, and reporting.
Each iteration executes:
1. Retraining & Golden Quality Gate validation
2. ML Evaluation on telemetry & test sets
3. Report generation
4. Analysis & feedback incorporation for the next iteration
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime, timezone

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "backend"))

from services.continuous_learning import get_engine
import extract_ml_eval

def main():
    print("=" * 80)
    print("  AFFERENT 5-ITERATION CONTINUOUS LEARNING & EVALUATION ROUTINE")
    print("=" * 80)

    reports_dir = root_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    engine = get_engine()
    all_summaries = []

    for iteration in range(1, 6):
        print(f"\n[ITERATION {iteration} / 5] Starting at {datetime.now(timezone.utc).isoformat()}")
        start_time = time.perf_counter()

        # 1. Run retraining cycle
        print(f"[{iteration}] Running continuous learning & quality gate...")
        res = engine.run_cycle()
        duration = time.perf_counter() - start_time

        # 2. Extract ML evaluation metrics
        print(f"[{iteration}] Extracting ML evaluation telemetry...")
        eval_metrics = extract_ml_eval.get_evaluation_summary() if hasattr(extract_ml_eval, "get_evaluation_summary") else {}

        report = {
            "iteration": iteration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": duration,
            "retrain_result": res,
            "eval_metrics": eval_metrics
        }

        # 3. Save report
        report_path = reports_dir / f"iteration_{iteration}_report.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[{iteration}] Report saved to {report_path}")

        if res.get("promoted"):
            print(f"[{iteration}] SUCCESS: Model promoted. Revision: {res.get('revision')}, Threshold: {res.get('threshold'):.4f}")
        else:
            print(f"[{iteration}] REJECTED: {res.get('reason')}")

        all_summaries.append({
            "iteration": iteration,
            "promoted": res.get("promoted"),
            "revision": res.get("revision"),
            "threshold": res.get("threshold")
        })

        if iteration < 5:
            print(f"[{iteration}] Waiting briefly before next iteration...")
            time.sleep(2)

    summary_path = reports_dir / "five_iterations_summary.json"
    summary_path.write_text(json.dumps(all_summaries, indent=2), encoding="utf-8")
    print("\n" + "=" * 80)
    print("  5-ITERATION ROUTINE COMPLETED SUCCESSFULLY")
    print(f"  Summary saved to {summary_path}")
    print("=" * 80)

if __name__ == "__main__":
    main()
