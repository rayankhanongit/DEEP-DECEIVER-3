/**
 * Button.  variant: primary | secondary | ghost | danger
 *          size: md | sm | icon
 * Icon-only buttons must pass `label` (becomes the accessible name).
 */
function Button({
  variant = "secondary",
  size = "md",
  icon: Icon,
  label,
  children,
  className = "",
  type = "button",
  ...props
}) {
  return (
    <button
      type={type}
      className={`btn btn-${variant} btn-${size} ${className}`}
      aria-label={size === "icon" ? label : undefined}
      title={size === "icon" ? label : undefined}
      {...props}
    >
      {Icon && <Icon size={size === "sm" ? 14 : 16} aria-hidden="true" />}
      {children}
    </button>
  );
}

export default Button;
