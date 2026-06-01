import assert from "node:assert/strict";
import test from "node:test";

import safeBash, { decideCommand } from "../../src/extension/safe-bash.ts";

test("safe_bash policy allows requested git, gt, and gh PR commands", () => {
	assert.deepEqual(decideCommand("git", ["rebase", "main"]), { action: "allow" });
	assert.deepEqual(decideCommand("gt", ["submit"]), { action: "allow" });
	assert.deepEqual(decideCommand("gt", ["sync"]), { action: "allow" });
	assert.deepEqual(decideCommand("gh", ["pr", "create", "--title", "T", "--body", "B"]), { action: "allow" });
});

test("safe_bash policy still confirms force flags and rejects unmodeled gh commands", () => {
	assert.deepEqual(decideCommand("gt", ["submit", "--force"]), { action: "confirm", reason: "force option" });
	assert.deepEqual(decideCommand("gt", ["submit", "--force-with-lease"]), { action: "confirm", reason: "force option" });
	assert.deepEqual(decideCommand("gh", ["issue", "create"]), { action: "block", reason: "only gh pr commands are allowlisted" });
});

test("safe_bash extension avoids action methods during extension load", () => {
	const calls: string[] = [];
	const unavailableDuringLoad = () => {
		throw new Error("action methods unavailable during extension load");
	};
	const fakePi = {
		registerTool(tool: { name: string }) {
			calls.push(`registerTool:${tool.name}`);
		},
		on(event: string) {
			calls.push(`on:${event}`);
		},
		getAllTools: unavailableDuringLoad,
		getActiveTools: unavailableDuringLoad,
		setActiveTools: unavailableDuringLoad,
	};

	safeBash(fakePi as Parameters<typeof safeBash>[0]);

	assert.deepEqual(calls, [
		"registerTool:safe_bash",
		"on:tool_call",
		"on:session_start",
		"on:before_agent_start",
	]);
});
