import { useEffect, useId, useRef } from "react";
import { X } from "lucide-react";

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

/**
 * Accessible modal dialog: role=dialog, aria-modal, labelled by its title,
 * focus moves in, Tab is trapped, Escape and backdrop click close it,
 * and focus returns to whatever opened it.
 */
function Dialog({ title, description, onClose, children, size = "md", variant = "dialog" }) {
  const titleId = useId();
  const descId = useId();
  const panel = useRef(null);

  useEffect(() => {
    const previous = document.activeElement;
    const node = panel.current;

    const first = node?.querySelector("[data-autofocus]") || node?.querySelector(FOCUSABLE);
    first?.focus();

    const onKey = (event) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
        return;
      }

      if (event.key !== "Tab" || !node) return;

      const items = [...node.querySelectorAll(FOCUSABLE)].filter(
        (el) => el.offsetParent !== null
      );

      if (items.length === 0) return;

      const head = items[0];
      const tail = items[items.length - 1];

      if (event.shiftKey && document.activeElement === head) {
        event.preventDefault();
        tail.focus();
      } else if (!event.shiftKey && document.activeElement === tail) {
        event.preventDefault();
        head.focus();
      }
    };

    document.addEventListener("keydown", onKey);

    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus?.();
    };
  }, [onClose]);

  return (
    <div
      className={variant === "sheet" ? "sheet-backdrop" : "sheet-backdrop dialog-backdrop"}
      onMouseDown={onClose}
    >
      <div
        ref={panel}
        className={`sheet sheet-${size}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="sheet-head">
          <div>
            <h2 id={titleId}>{title}</h2>
            {description && <p id={descId}>{description}</p>}
          </div>

          <button
            type="button"
            className="btn btn-ghost btn-icon"
            onClick={onClose}
            aria-label="Close dialog"
          >
            <X size={22} aria-hidden="true" />
          </button>
        </header>

        <div className="sheet-body">{children}</div>
      </div>
    </div>
  );
}

export default Dialog;
