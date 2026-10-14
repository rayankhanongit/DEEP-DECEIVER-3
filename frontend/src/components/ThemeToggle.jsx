import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

const KEY = "dd_theme";

const current = () => (document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark");

function saved() {
  try {
    const v = localStorage.getItem(KEY);

    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

function apply(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "light" ? "#f3f1fa" : "#09080f");
}

/** Light/dark switch. A saved choice wins; otherwise the OS preference is followed live. */
function ThemeToggle() {
  const [theme, setTheme] = useState(current);

  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: light)");

    const follow = (event) => {
      if (saved()) return;                             // an explicit choice is never overwritten

      const next = event.matches ? "light" : "dark";

      apply(next);
      setTheme(next);
    };

    query.addEventListener("change", follow);

    return () => query.removeEventListener("change", follow);
  }, []);

  const toggle = () => {
    const next = theme === "light" ? "dark" : "light";
    const root = document.documentElement;

    root.classList.add("theme-anim");
    apply(next);
    setTheme(next);

    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* storage unavailable: the choice lasts for this visit only */
    }

    setTimeout(() => root.classList.remove("theme-anim"), 300);
  };

  const light = theme === "light";

  return (
    <button
      type="button"
      className="nav-toggle"
      onClick={toggle}
      aria-pressed={!light}
      aria-label="Dark theme"
      title={light ? "Switch to dark theme" : "Switch to light theme"}
    >
      {light ? <Moon size={20} aria-hidden="true" /> : <Sun size={20} aria-hidden="true" />}
    </button>
  );
}

export default ThemeToggle;
