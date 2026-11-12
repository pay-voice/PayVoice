import os from "os";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Resolves the mutable data directory for encrypted vault & audit files.
 * Uses the OS temporary directory (/tmp) when deployed in read-only serverless runtimes (e.g. Netlify / AWS Lambda).
 */
export function resolveDataDir() {
  const isServerless = Boolean(
    process.env.NETLIFY ||
    process.env.AWS_LAMBDA_FUNCTION_NAME ||
    process.env.LAMBDA_TASK_ROOT ||
    process.env.VERCEL
  );
  if (isServerless) {
    return path.join(os.tmpdir(), "payvoice-data");
  }
  return path.resolve(__dirname, "../data");
}

