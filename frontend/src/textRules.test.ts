import { describe, expect, it } from "vitest";
import { forbiddenInText, stripForbidden } from "./textRules";

describe("text rules", () => {
  it("flags dashes and emoji", () => {
    expect(forbiddenInText("hello — world")).toBe(true);
    expect(forbiddenInText("a -- b")).toBe(true);
    expect(forbiddenInText("plain text")).toBe(false);
  });

  it("strips forbidden characters", () => {
    expect(stripForbidden("Alert — next -- step")).toBe("Alert next step");
  });
});
