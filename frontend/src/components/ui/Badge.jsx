import { SEVERITY_TONE, STATES, stateFor } from "./status";

/** Generic pill. tone: neutral | accent | ok | warn | crit | info */
export function Badge({ tone = "neutral", icon: Icon, children, className = "" }) {
  return (
    <span className={`badge badge-${tone} ${className}`}>
      {Icon && <Icon size={12} aria-hidden="true" />}
      {children}
    </span>
  );
}

/** One of the five security states: icon + label + tone. */
export function StatusBadge({ state, label, ...rest }) {
  const key = state || stateFor(rest);
  const { label: defaultLabel, tone, Icon } = STATES[key] || STATES.warning;

  return (
    <Badge tone={tone} icon={Icon}>
      {label || defaultLabel}
    </Badge>
  );
}

/** LOW / MEDIUM / HIGH / CRITICAL, always spelled out. */
export function SeverityBadge({ level }) {
  return <Badge tone={SEVERITY_TONE[level] || "neutral"}>{level}</Badge>;
}
