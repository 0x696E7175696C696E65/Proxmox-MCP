import { describe, expect, it } from "vitest";
import { censorText } from "./privacy";

describe("censorText", () => {
  it("masks IPv4 addresses", () => {
    expect(censorText("https://192.168.10.168:8006")).toContain("•••.••.••.•••");
    expect(censorText("https://192.168.10.168:8006")).not.toContain("192.168");
  });

  it("masks credential paths", () => {
    expect(censorText("clusters/homelab/proxmox-api")).toBe("clusters/••••/••••");
  });

  it("leaves plain labels alone", () => {
    expect(censorText("Networking Node")).toBe("Networking Node");
  });
});
