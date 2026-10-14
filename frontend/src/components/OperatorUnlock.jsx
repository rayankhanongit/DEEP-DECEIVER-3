import { useState } from "react";
import { CircleAlert, KeyRound } from "lucide-react";

import { getJSON, setOperatorToken } from "../api";
import Button from "./ui/Button";
import Dialog from "./ui/Dialog";

function OperatorUnlock({ onClose, onUnlocked }) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();

    if (!token.trim() || busy) return;

    setBusy(true);
    setError("");
    setOperatorToken(token.trim());

    try {
      await getJSON("/security/status");
      onUnlocked();
    } catch {
      setOperatorToken("");
      setError("That token wasn't accepted. Check OPERATOR_TOKEN in your .env file.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      title="Operator access"
      description="Enter the operator token from your .env file to open the security views."
      onClose={onClose}
      size="sm"
    >
      <form onSubmit={submit} noValidate>
        <label className="field-label" htmlFor="operator-token">
          Operator token
        </label>

        <input
          id="operator-token"
          className="field-input"
          type="password"
          name="operator-token"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? "operator-error" : undefined}
          data-autofocus
        />

        {error && (
          <div id="operator-error" className="form-error" role="alert">
            <CircleAlert size={16} aria-hidden="true" />
            {error}
          </div>
        )}

        <div className="dialog-actions">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>

          <Button
            variant="primary"
            type="submit"
            icon={KeyRound}
            disabled={busy || !token.trim()}
          >
            {busy ? "Checking…" : "Unlock"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export default OperatorUnlock;
