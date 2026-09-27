import { execFileSync } from "node:child_process";
import { error, log } from "node:console";
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";

if (process.argv[2] !== "secrets") {
  error("usage: node scripts/security-scan.mjs secrets");
  process.exit(2);
}

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  encoding: "utf8",
}).trim();
const files = execFileSync(
  "git",
  ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
  { cwd: root, encoding: "utf8" },
)
  .split("\0")
  .filter(Boolean);

const textExtensions = new Set([
  ".cjs",
  ".css",
  ".html",
  ".js",
  ".json",
  ".jsx",
  ".md",
  ".mjs",
  ".pem",
  ".py",
  ".sh",
  ".sql",
  ".tf",
  ".ts",
  ".tsx",
  ".txt",
  ".yaml",
  ".yml",
]);

const patterns = [
  { name: "AWS access key", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  {
    name: "private key block",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  { name: "GitHub token", regex: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/g },
  { name: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g },
  { name: "OpenAI-style key", regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g },
  { name: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
  { name: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

const findings = [];
for (const file of [...new Set(files)].sort()) {
  const extension = path.extname(file).toLowerCase();
  if (!textExtensions.has(extension) && path.basename(file) !== "Dockerfile") {
    continue;
  }
  const absolutePath = path.join(root, file);
  if (!existsSync(absolutePath) || statSync(absolutePath).size > 5_000_000) {
    continue;
  }
  const buffer = readFileSync(absolutePath);
  if (buffer.includes(0)) {
    continue;
  }
  const source = buffer.toString("utf8");
  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    for (const match of source.matchAll(pattern.regex)) {
      findings.push({
        file,
        line: source.slice(0, match.index ?? 0).split("\n").length,
        rule: pattern.name,
      });
    }
  }
}

if (findings.length > 0) {
  for (const finding of findings) {
    error(`${finding.file}:${finding.line} ${finding.rule}`);
  }
  process.exit(1);
}

log("security:secrets passed");
