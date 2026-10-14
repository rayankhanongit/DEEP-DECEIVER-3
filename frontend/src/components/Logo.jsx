import { useId } from "react";

/** DEEP-DECEIVER mark: a shield with a watching eye. */
function Logo({ size = 28, className = "" }) {
  // Unique gradient id per instance so several logos can coexist.
  const id = `dd-grad-${useId().replace(/:/g, "")}`;

  return (
    <svg
      className={`logo ${className}`}
      width={size}
      height={size}
      viewBox="0 0 64 64"
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#c4b5fd" />
          <stop offset="1" stopColor="#8b5cf6" />
        </linearGradient>
      </defs>

      <path
        d="M32 4 56 13v17c0 14-10 25-24 30C18 55 8 44 8 30V13z"
        fill={`url(#${id})`}
      />
      <path
        d="M32 16 46 21v9c0 8-5 14-14 18-9-4-14-10-14-18v-9z"
        fill="#0b1020"
      />
      <circle className="logo-eye" cx="32" cy="30" r="6" fill={`url(#${id})`} />
      <circle cx="32" cy="30" r="2.4" fill="#0b1020" />
    </svg>
  );
}

export default Logo;
