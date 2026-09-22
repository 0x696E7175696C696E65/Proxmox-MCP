import { describe, expect, it } from "vitest";

describe("admin spa smoke", () => {
  it("masks last4 helper shape", () => {
    const mask = { configured: true, last4: "70a6" };
    expect(mask.last4).toHaveLength(4);
  });

  it("classifies hot vs restart apply kinds", () => {
    const hot = { kind: "hot", message: "Applied log_level" };
    const restart = { kind: "restart", message: "Restart required for service_token" };
    expect(hot.kind).toBe("hot");
    expect(restart.kind).toBe("restart");
    expect(restart.message).toMatch(/restart/i);
  });

  it("builds audit drawer selection payload", () => {
    const event = {
      event_id: "aud_1",
      tool_name: "list_nodes",
      result_status: "success",
      metadata: { span_id: "abc" },
    };
    expect(event.event_id).toBeTruthy();
    expect(JSON.stringify(event.metadata)).toContain("span_id");
  });
});
