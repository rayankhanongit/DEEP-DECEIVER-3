export const API = "http://127.0.0.1:8000";

const TOKEN_KEY = "dd_operator_token";

export function getOperatorToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function setOperatorToken(token) {
  try {
    if (token) {
      sessionStorage.setItem(TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    /* storage unavailable */
  }
}

/** Headers that identify the operator (empty for ordinary chat users). */
export function authHeaders() {
  const token = getOperatorToken();

  return token ? { "X-Operator-Token": token } : {};
}

export async function getJSON(path) {
  const response = await fetch(`${API}${path}`, { headers: authHeaders() });

  if (!response.ok) {
    throw new Error(`${path} failed (${response.status})`);
  }

  return response.json();
}

export async function postJSON(path, body) {
  const response = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(body ?? {}),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const detail =
      typeof data.detail === "string"
        ? data.detail
        : `${path} failed (${response.status})`;

    throw new Error(detail);
  }

  return data;
}

export const SEVERITY_ORDER = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

export function prettyCategory(category) {
  return String(category || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

const TIME_FORMAT = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export function formatTime(iso) {
  if (!iso) return "";

  const date = new Date(iso);

  return Number.isNaN(date.getTime()) ? "" : TIME_FORMAT.format(date);
}
