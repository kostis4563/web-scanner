#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const DAY = 24 * 60 * 60 * 1000;
const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "activity.json");
const args = process.argv.slice(2);
const count = Number(args.find((a) => /^\d+$/.test(a)) ?? 100);
const push = args.includes("--push");
const day = args.find((a) => a.startsWith("--day="))?.slice("--day=".length);
if (day && Number.isNaN(Date.parse(`${day}T00:00:00`))) throw new Error(`Invalid --day: ${day}`);

const git = (argv, env = {}) =>
  execFileSync("git", argv, { stdio: "inherit", env: { ...process.env, ...env } });

const localIso = (d) => {
  const offset = -d.getTimezoneOffset();
  const pad = (n) => String(Math.trunc(Math.abs(n))).padStart(2, "0");
  const local = new Date(d.getTime() + offset * 60 * 1000).toISOString().slice(0, 19);
  return `${local}${offset >= 0 ? "+" : "-"}${pad(offset / 60)}:${pad(offset % 60)}`;
};

const randomDate = day
  ? () => new Date(Date.parse(`${day}T00:00:00`) + Math.random() * DAY)
  : () => new Date(Date.now() - Math.random() * 365 * DAY);
const dates = Array.from({ length: count }, randomDate).sort((a, b) => a - b);

for (const d of dates) {
  const date = localIso(d);
  writeFileSync(file, JSON.stringify({ date }, null, 2) + "\n");
  git(["add", file]);
  git(["commit", "--quiet", "-m", date, "--", file], { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date });
}

console.log(`Created ${count} commits.`);
if (push) git(["push"]);
