import {
  OctagonAlert,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  TriangleAlert,
} from "lucide-react";

/**
 * Security states shown everywhere. Every state has an icon AND a text
 * label so meaning never depends on colour alone.
 */
export const STATES = {
  safe: { label: "Safe", tone: "ok", Icon: ShieldCheck },
  blocked: { label: "Blocked attempt", tone: "ok", Icon: ShieldAlert },
  warning: { label: "Warning", tone: "warn", Icon: TriangleAlert },
  critical: { label: "Critical", tone: "crit", Icon: OctagonAlert },
  jailbreak: { label: "Successful jailbreak", tone: "crit", Icon: ShieldX },
};

/** Map an event outcome + severity to one of the five states. */
export function stateFor({ outcome, severity, jailbreakSuccess } = {}) {
  if (jailbreakSuccess || outcome === "SUCCESS") return "jailbreak";
  if (severity === "CRITICAL") return "critical";
  if (outcome === "SUSPICIOUS" || severity === "HIGH" || severity === "MEDIUM") {
    return outcome === "BLOCKED" ? "blocked" : "warning";
  }
  if (outcome === "BLOCKED") return "blocked";
  if (outcome === "SAFE") return "safe";
  return "warning";
}

export const SEVERITY_TONE = {
  SAFE: "ok",
  LOW: "info",
  MEDIUM: "warn",
  HIGH: "warn",
  CRITICAL: "crit",
};
