import { describe, expect, it } from "vitest";
import { diagnosisLine, shareableSummary } from "./pages/AuditPage";
import type { AuditEvent } from "./api";

function event(partial: Partial<AuditEvent>): AuditEvent {
  return {
    event_id: "aud_1",
    timestamp: "2026-09-23T12:00:00Z",
    tool_name: "start_vm",
    operation: "vm.lifecycle.start",
    actor_user_id: "u1",
    actor_agent_id: "a1",
    result_status: "denied",
    error_code: "TOOL_NOT_GRANTED",
    metadata: { denial_reason: "TOOL_NOT_GRANTED", matched_rule: "start_vm" },
    ...partial,
  };
}

describe("audit detail diagnosis", () => {
  it("explains TOOL_NOT_GRANTED for MSP triage", () => {
    const line = diagnosisLine(event({}));
    expect(line.toLowerCase()).toContain("capability");
    expect(line.toLowerCase()).toMatch(/grant|acl|deny/);
  });

  it("builds shareable summary with denial reason", () => {
    const summary = shareableSummary(event({}));
    expect(summary).toContain("event_id=aud_1");
    expect(summary).toContain("denial=TOOL_NOT_GRANTED");
    expect(summary).toContain("status=denied");
  });

  it("explains success without error chrome", () => {
    const line = diagnosisLine(
      event({ result_status: "success", error_code: null, metadata: {} }),
    );
    expect(line.toLowerCase()).toContain("success");
  });
});
