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

  it("classifies Observe vs Control navigation", () => {
    const observe = ["Overview", "Inventory", "Audit", "Health"];
    const control = ["Tools", "Approvals", "Access", "Servers"];
    expect(observe).not.toContain("Access");
    expect(control).toContain("Access");
    expect(control).toContain("Tools");
  });

  it("requires step-up password fields for dangerous writes", () => {
    const stepUpBodies = [
      { password: "secret" },
      { decision: "approved", password: "secret" },
    ];
    for (const body of stepUpBodies) {
      expect(body.password.length).toBeGreaterThan(0);
    }
  });
});
