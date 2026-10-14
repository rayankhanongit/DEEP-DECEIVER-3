import { useEffect, useRef, useState } from "react";
import { LoaderCircle } from "lucide-react";

import { SEVERITY_TONE } from "./status";

export function Card({ as: Tag = "section", className = "", children, ...props }) {
  return (
    <Tag className={`glass ${className}`} {...props}>
      {children}
    </Tag>
  );
}

/** Animates a number toward its new value (static when motion is reduced). */
export function CountUp({ value, suffix = "", decimals }) {
  const target = Number(value) || 0;
  const [shown, setShown] = useState(target);
  const from = useRef(target);

  useEffect(() => {
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    if (reduced) {
      from.current = target;
      const id = requestAnimationFrame(() => setShown(target));
      return () => cancelAnimationFrame(id);
    }

    const origin = from.current;
    const start = performance.now();
    let frame;

    const tick = (now) => {
      const t = Math.min(1, (now - start) / 650);
      const eased = 1 - Math.pow(1 - t, 3);

      setShown(origin + (target - origin) * eased);

      if (t < 1) {
        frame = requestAnimationFrame(tick);
      } else {
        from.current = target;
      }
    };

    frame = requestAnimationFrame(tick);

    return () => cancelAnimationFrame(frame);
  }, [target]);

  const digits = decimals ?? (Number.isInteger(target) ? 0 : 1);

  return (
    <>
      {new Intl.NumberFormat(undefined, {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      }).format(shown)}
      {suffix}
    </>
  );
}

export function MetricCard({ label, value, suffix, tone, icon: Icon, className = "" }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""} ${className}`}>
      <div className="stat-label">
        {Icon && <Icon size={18} aria-hidden="true" />}
        {label}
      </div>

      <div className="stat-value">
        <CountUp value={value} suffix={suffix} />
      </div>
    </div>
  );
}

/** Ring gauge; the level is written out so colour is never the only cue. */
export function RiskMeter({ value, level, size = 220 }) {
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, value));
  const offset = circumference * (1 - clamped / 100);
  const tone = SEVERITY_TONE[level] || "info";

  return (
    <div
      className="risk-meter"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Average risk ${Math.round(clamped)} out of 100, level ${level}`}
    >
      <svg viewBox="0 0 160 160" width={size} height={size} aria-hidden="true">
        <circle className="meter-track" cx="80" cy="80" r={radius} />
        <circle
          className={`meter-fill meter-${tone}`}
          cx="80"
          cy="80"
          r={radius}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 80 80)"
        />
      </svg>

      <div className="meter-label">
        <strong className="risk-number">
          <CountUp value={clamped} decimals={0} />
        </strong>
        <span>{level}</span>
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon, title, children, action }) {
  return (
    <div className="empty">
      {Icon && <Icon size={28} aria-hidden="true" />}
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Spinner({ label = "Loading" }) {
  return (
    <span className="spinner" role="status">
      <LoaderCircle size={16} aria-hidden="true" />
      <span className="sr-only">{label}</span>
    </span>
  );
}
