import { readFileSync } from "node:fs";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

type Decision =
  | { action: "allow" }
  | { action: "confirm"; reason: string }
  | { action: "block"; reason: string };

type SafeCommandParams = {
  command: string;
  args?: string[];
  timeoutMs?: number;
};

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;

/**
 * Policy model:
 * - exact allow rules run without prompting;
 * - risky-but-legitimate rules prompt the user when UI is available;
 * - everything else is denied by default.
 *
 * Keep this tool argv-based via `pi.exec(command, args)` rather than shell-string
 * based. That avoids shell expansion, pipes, redirects, command substitution, and
 * multi-command edit tricks. It is not a complete sandbox: some executables have
 * their own execution/write features, so each allowlisted command also needs
 * command-specific flag checks below. Git read-only commands may still honor local
 * git aliases/config, so this policy assumes the current repository's git config
 * is trusted. File reads/writes/edits should use Pi's built-in read/write/edit
 * tools instead.
 */
type PolicyAction = "allow" | "ask" | "deny";

type PolicyRule = {
  command: string | string[];
  args?: string[];
  argsPrefix?: string[];
  unlessArgs?: string[];
  unlessArgsPrefix?: string[];
  subcommands?: string[];
  subcommandIndex?: number;
  hasAnyArg?: string[];
  predicate?: string;
  reason?: string;
  reasonTemplate?: string;
};

type SafeBashPolicy = {
  default: "deny";
  deny: PolicyRule[];
  ask: PolicyRule[];
  allow: PolicyRule[];
};

const POLICY_URL = new URL("./safe-bash-policy.json", import.meta.url);
const DEFAULT_POLICY = loadPolicy();

function loadPolicy(): SafeBashPolicy {
  const overridePath = process.env.PI_SAFE_BASH_POLICY;
  return JSON.parse(readFileSync(overridePath || POLICY_URL, "utf8")) as SafeBashPolicy;
}

export function decideCommand(command: string, args: string[], policy: SafeBashPolicy = DEFAULT_POLICY): Decision {
  const denyRule = findMatchingRule(policy.deny, command, args);
  if (denyRule) return { action: "block", reason: renderReason(denyRule, command, args) ?? defaultBlockReason(command, args) };

  const askRule = findMatchingRule(policy.ask, command, args);
  if (askRule) return { action: "confirm", reason: renderReason(askRule, command, args) ?? "command requires confirmation" };

  const allowRule = findMatchingRule(policy.allow, command, args);
  if (allowRule) return { action: "allow" };

  return { action: "block", reason: defaultBlockReason(command, args) };
}

function findMatchingRule(rules: PolicyRule[], command: string, args: string[]): PolicyRule | undefined {
  return rules.find((rule) => matchesRule(rule, command, args));
}

function matchesRule(rule: PolicyRule, command: string, args: string[]): boolean {
  if (!matchesCommand(rule.command, command)) return false;
  if (rule.args && !arrayEquals(args, rule.args)) return false;
  if (rule.argsPrefix && !startsWithArray(args, rule.argsPrefix)) return false;
  if (rule.unlessArgs && arrayEquals(args, rule.unlessArgs)) return false;
  if (rule.unlessArgsPrefix && startsWithArray(args, rule.unlessArgsPrefix)) return false;
  if (rule.subcommands && !rule.subcommands.includes(args[rule.subcommandIndex ?? 0] ?? "")) return false;
  if (rule.hasAnyArg && !hasAnyArg(args, rule.hasAnyArg)) return false;
  if (rule.predicate && !matchesNamedPredicate(rule.predicate, command, args)) return false;
  return true;
}

function matchesCommand(expected: string | string[], command: string): boolean {
  if (expected === "*") return true;
  return Array.isArray(expected) ? expected.includes(command) : expected === command;
}

function arrayEquals(actual: string[], expected: string[]): boolean {
  return actual.length === expected.length && actual.every((arg, index) => arg === expected[index]);
}

function startsWithArray(actual: string[], prefix: string[]): boolean {
  return prefix.every((arg, index) => actual[index] === arg);
}

function renderReason(rule: PolicyRule, _command: string, args: string[]): string | undefined {
  if (rule.reason) return rule.reason;
  if (!rule.reasonTemplate) return undefined;
  const subcommand = args[0] || "<none>";
  return rule.reasonTemplate
    .replaceAll("{subcommand}", subcommand)
    .replaceAll("{subcommandOr:install}", args[0] || "install");
}

function defaultBlockReason(command: string, args: string[]): string {
  if (["npm", "pnpm", "yarn"].includes(command)) {
    return `package manager subcommand is not allowlisted: ${args[0] || "<none>"}`;
  }
  if (command === "gh" && args[0] === "pr") {
    return `gh pr subcommand is not allowlisted: ${args[1] || "<none>"}`;
  }
  return `command is not allowlisted: ${command}`;
}

function matchesNamedPredicate(predicate: string, _command: string, args: string[]): boolean {
  switch (predicate) {
    case "find-dangerous-flag":
      return Boolean(args.find((arg) => ["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"].includes(arg)));
    case "rg-dangerous-flag":
      return Boolean(args.find((arg) => arg === "--pre" || arg.startsWith("--pre=") || arg === "--pre-glob" || arg.startsWith("--pre-glob=") || arg === "--search-zip" || arg === "-z"));
    case "git-readonly-risky-flag":
      return ["status", "diff", "log", "show"].includes(args[0] ?? "") && Boolean(args.find((arg) => arg === "--output" || arg.startsWith("--output=") || arg === "--ext-diff" || arg === "--no-pager" || arg.startsWith("--exec-path")));
    case "git-branch-mutating":
      return (args[0] ?? "") === "branch" && !isGitBranchReadOnly(args);
    case "git-push-delete-ref":
      return (args[0] ?? "") === "push" && (hasAnyArg(args, ["--delete"]) || args.some((arg) => arg.startsWith(":")));
    case "git-clean-removes-files":
      return (args[0] ?? "") === "clean" && args.some((arg) => /^-[A-Za-z]*[fdx]/.test(arg));
    case "git-checkout-overwrite":
      return (args[0] ?? "") === "checkout" && args.includes("--");
    case "git-restore-discard":
      return (args[0] ?? "") === "restore" && args.some((arg) => arg === "--source" || arg.startsWith("--source=") || arg === "--staged" || arg === "--worktree" || arg === ".");
    case "gh-non-pr":
      return args[0] !== "pr";
    case "gh-pr-edit-body-file":
      return args[0] === "pr" && args[1] === "edit" && hasBodyFileArg(args);
    default:
      return false;
  }
}

function isGitBranchReadOnly(args: string[]): boolean {
  const branchArgs = args.slice(1);
  if (branchArgs.length === 0) return true;
  const readOnlyFlags = new Set(["--all", "--remotes", "--list", "--show-current", "--verbose", "--vv", "-a", "-r", "-l", "-v", "-vv"]);
  const hasListFlag = branchArgs.some((arg) => readOnlyFlags.has(arg));
  return hasListFlag && branchArgs.every((arg) => readOnlyFlags.has(arg) || !arg.startsWith("-"));
}

function hasBodyFileArg(args: string[]): boolean {
  return args.some((arg, index) => arg === "--body-file" ? Boolean(args[index + 1]) : arg.startsWith("--body-file=") && arg.length > "--body-file=".length);
}

function hasAnyArg(args: string[], candidates: string[]): boolean {
  return args.some((arg) => candidates.includes(arg));
}

function formatCommand(command: string, args: string[]): string {
  return [command, ...args].join(" ");
}

function sanitizeCommandName(command: string): string | null {
  const trimmed = command.trim();
  if (!/^[A-Za-z0-9_.+-]+$/.test(trimmed)) return null;
  return trimmed;
}

export default function safeBash(pi: ExtensionAPI) {
  const globalStore = globalThis as Record<string, unknown>;
  const registeredKey = "__piSubagentsSafeBashRegisteredApis";
  const registeredApis = globalStore[registeredKey] instanceof WeakSet
    ? globalStore[registeredKey] as WeakSet<ExtensionAPI>
    : new WeakSet<ExtensionAPI>();
  globalStore[registeredKey] = registeredApis;

  if (registeredApis.has(pi)) return;
  if (pi.getAllTools().some((tool) => tool.name === "safe_bash")) {
    registeredApis.add(pi);
    return;
  }
  registeredApis.add(pi);


  pi.registerTool({
    name: "safe_bash",
    label: "Safe Bash",
    description: "Run an allowlisted command using explicit argv args. Denies by default and never invokes a shell.",
    promptSnippet: "Run allowlisted inspection/test/git commands with explicit argv args. Do not use for file edits.",
    promptGuidelines: [
      "Use safe_bash for allowlisted commands such as git/gt inspection, limited gh pr commands, tests, rg, find, ls, and pwd.",
      "Use read/write/edit tools for file contents and edits; do not use safe_bash for cat/sed/awk/python/node/perl file edits or multi-command shell scripts.",
      "safe_bash denies unmodeled commands by default and prompts the user for risky commands such as git commit --no-verify, git push --force, git push --force-with-lease, and git reset --hard."
    ],
    parameters: Type.Object({
      command: Type.String({ description: "Executable name, e.g. git, rg, pytest. No shell syntax." }),
      args: Type.Optional(Type.Array(Type.String(), { description: "Argument vector. No shell syntax or command chaining." })),
      timeoutMs: Type.Optional(Type.Number({ description: "Timeout in milliseconds, capped at 600000." })),
    }),
    async execute(_toolCallId, params: SafeCommandParams, signal, _onUpdate, ctx) {
      const command = sanitizeCommandName(params.command);
      const args = params.args ?? [];

      if (!command) {
        return { isError: true, content: [{ type: "text", text: `Blocked: invalid command name: ${params.command}` }] };
      }

      const decision = decideCommand(command, args);
      if (decision.action === "block") {
        return { isError: true, content: [{ type: "text", text: `Blocked: ${decision.reason}\n${formatCommand(command, args)}` }] };
      }

      if (decision.action === "confirm") {
        if (!ctx.hasUI) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: `Confirmation required for safe_bash command, but no interactive UI is available: ${decision.reason}\n${formatCommand(command, args)}`,
              },
            ],
          };
        }

        let ok = false;
        try {
          ok = await ctx.ui.confirm(
            "Confirm safe_bash command",
            `Reason: ${decision.reason}\n\nCommand:\n${formatCommand(command, args)}`,
            { signal },
          );
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          return { isError: true, content: [{ type: "text", text: `Confirmation failed closed: ${message}` }] };
        }
        if (!ok) {
          return { isError: true, content: [{ type: "text", text: `Declined: ${decision.reason}` }] };
        }
      }

      const requestedTimeout = Number.isFinite(params.timeoutMs) ? params.timeoutMs : DEFAULT_TIMEOUT_MS;
      const timeout = Math.min(Math.max(requestedTimeout ?? DEFAULT_TIMEOUT_MS, 1_000), MAX_TIMEOUT_MS);

      try {
        const result = await pi.exec(command, args, { signal, timeout, cwd: ctx.cwd });
        const output = [result.stdout, result.stderr].filter(Boolean).join("\n");

        return {
          isError: result.code !== 0,
          content: [{ type: "text", text: output || `(exit ${result.code})` }],
          details: result,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { isError: true, content: [{ type: "text", text: `Execution failed: ${message}` }] };
      }
    },
  });

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return;
    if (ctx.hasUI) ctx.ui.notify("Blocked agent bash; use safe_bash instead.", "error");
    return { block: true, reason: "Agent bash is disabled. Use safe_bash for allowlisted commands." };
  });

  pi.on("session_start", async () => {
    const activeTools = pi.getActiveTools().filter((name) => name !== "bash");
    if (!activeTools.includes("safe_bash")) activeTools.push("safe_bash");
    pi.setActiveTools(activeTools);
  });

  pi.on("before_agent_start", async (event) => ({
    systemPrompt: `${event.systemPrompt}

## Safe command policy

- Built-in agent bash is disabled; use safe_bash only for allowlisted commands.
- User-initiated bash remains available when the Pi UI/runtime provides it.
- safe_bash is argv-based and denies by default. It is for tests, inspection, and narrowly approved git/gh/gt commands.
- Use read, write, edit, grep, find, and ls tools for file operations. Do not use safe_bash to read, write, patch, or multi-edit files.
- Risky commands require user approval by policy, e.g. --force/--force-with-lease, git commit --no-verify, git reset --hard, git clean, and GitHub PR metadata edits.
`,
  }));
}
