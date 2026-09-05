import { describe, it, expect } from "bun:test";
import { initialsFor } from "../src/frontend/components/Avatar";

const u = (name: string, email = "someone@example.com") => ({ name, email });

describe("initialsFor", () => {
  it("takes the first two words of a display name", () => {
    expect(initialsFor(u("Ajey Gore"))).toBe("AG");
    expect(initialsFor(u("ada lovelace"))).toBe("AL");
  });

  it("stops at two, however many names there are", () => {
    expect(initialsFor(u("Jean Baptiste Emanuel Zorg"))).toBe("JB");
  });

  it("handles a single name", () => {
    expect(initialsFor(u("Prince"))).toBe("P");
  });

  // Google returns no name for some accounts, so the address is the fallback —
  // and the domain must not leak into the initials.
  it("falls back to the address, using only the local part", () => {
    expect(initialsFor({ name: "", email: "ajey.gore@tnkrhaus.dev" })).toBe("AG");
    expect(initialsFor({ name: "", email: "ajey@tnkrhaus.dev" })).toBe("A");
    expect(initialsFor({ name: "", email: "first_last@example.com" })).toBe("FL");
    expect(initialsFor({ name: "", email: "first-last@example.com" })).toBe("FL");
    expect(initialsFor({ name: "", email: "user+tag@example.com" })).toBe("UT");
  });

  it("never returns an empty string", () => {
    expect(initialsFor({ name: "", email: "" })).toBe("?");
    expect(initialsFor({ name: "   ", email: "" })).toBe("?");
    expect(initialsFor({ name: "...", email: "" })).toBe("?");
  });

  it("copes with unicode names", () => {
    expect(initialsFor(u("Ólafur Árnason"))).toBe("ÓÁ");
  });
});
