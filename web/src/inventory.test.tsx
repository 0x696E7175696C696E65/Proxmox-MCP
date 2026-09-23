import { describe, expect, it } from "vitest";
import { StatusBadge, UtilizationBar } from "./pages/InventoryPage";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

describe("inventory utilization UI", () => {
  it("renders utilization percent from fixture", () => {
    const html = renderToStaticMarkup(
      createElement(UtilizationBar, { percent: 42.5, label: "cpu" }),
    );
    expect(html).toMatch(/4[23]%/);
    expect(html).toContain("width:42.5%");
  });

  it("compact mode omits use label", () => {
    const html = renderToStaticMarkup(
      createElement(UtilizationBar, { percent: 12, compact: true }),
    );
    expect(html).not.toContain(">use<");
    expect(html).toContain("12%");
  });

  it("renders online status badge", () => {
    const html = renderToStaticMarkup(createElement(StatusBadge, { status: "running" }));
    expect(html).toContain("running");
    expect(html.toLowerCase()).toMatch(/emerald|running/);
  });

  it("handles missing utilization without crashing", () => {
    const html = renderToStaticMarkup(createElement(UtilizationBar, { percent: null }));
    expect(html).toContain("—");
  });
});
