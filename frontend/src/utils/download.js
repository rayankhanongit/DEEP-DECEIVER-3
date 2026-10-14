/**
 * Client-side file export (no server round trip).
 */

// UTF-8 byte-order mark so Excel opens the file with the right encoding.
const BOM = String.fromCharCode(0xfeff);

// Cells that a spreadsheet would run as a formula are prefixed with an
// apostrophe, so an attacker-supplied prompt such as "=HYPERLINK(...)" in an
// exported event cannot execute when the CSV is opened in Excel.
const FORMULA_START = /^[=+\-@\t\r]/;

function csvCell(value) {
  if (value === null || value === undefined) return "";

  let text =
    typeof value === "object" ? JSON.stringify(value) : String(value);

  if (FORMULA_START.test(text)) {
    text = `'${text}`;
  }

  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/** Rows (array of objects) -> CSV text with a header row. */
export function toCsv(rows, columns) {
  const keys =
    columns ||
    [...new Set(rows.flatMap((row) => Object.keys(row)))];

  const lines = [
    keys.map(csvCell).join(","),
    ...rows.map((row) => keys.map((key) => csvCell(row[key])).join(",")),
  ];

  const EOL = String.fromCharCode(13, 10);

  return BOM + lines.join(EOL) + EOL;
}

export function toJson(data) {
  return `${JSON.stringify(data, null, 2)}\n`;
}

export function downloadText(filename, text, mime) {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();

  // Give the browser a moment to start the download before releasing.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Local timestamp safe for file names, e.g. 2026-10-09_14-32-05 */
export function fileStamp(when) {
  const parsed = when ? new Date(when) : new Date();
  const date = Number.isNaN(parsed.getTime()) ? new Date() : parsed;

  const pad = (n) => String(n).padStart(2, "0");

  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `_${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`
  );
}
