/**
 * PayVoice Test Runner -> Delegates to scripts/benchmark.js
 */
import { runFullBenchmark } from "../../scripts/benchmark.js";

runFullBenchmark()
  .then((res) => {
    process.exit(res.passed ? 0 : 1);
  })
  .catch((err) => {
    console.error("Benchmark Fatal Error:", err);
    process.exit(1);
  });
