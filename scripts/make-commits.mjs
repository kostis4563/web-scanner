#!/usr/bin/env node
// Backfills the GitHub contribution graph with commits spread over the past year.
// Usage: node scripts/make-commits.mjs [count=100] [--push]
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const DAY = 24 * 60 * 60 * 1000;
const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "activity.json");
const args = process.argv.slice(2);
const count = Number(args.find((a) => /^\d+$/.test(a)) ?? 100);
const push = args.includes("--push");

const git = (argv, env = {}) =>
  execFileSync("git", argv, { stdio: "inherit", env: { ...process.env, ...env } });

// Random moments within the last 365 days (never in the future), oldest first.
const dates = Array.from({ length: count }, () => new Date(Date.now() - Math.random() * 365 * DAY))
  .sort((a, b) => a - b);

for (const d of dates) {
  const date = d.toISOString();
  writeFileSync(file, JSON.stringify({ date }, null, 2) + "\n");
  git(["add", file]);
  // Paths after `--` commit only this file, so unrelated staged changes are left alone.
  git(["commit", "--quiet", "-m", date, "--", file], { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date });
}

console.log(`Created ${count} commits.`);
if (push) git(["push"]);
