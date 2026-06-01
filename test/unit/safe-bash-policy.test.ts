import assert from "node:assert/strict";
import test from "node:test";

import { decideCommand } from "../../src/extension/safe-bash.ts";

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
