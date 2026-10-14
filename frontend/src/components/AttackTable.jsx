import { Download, FileJson, FileSpreadsheet } from "lucide-react";

import Button from "./ui/Button";
import { downloadText, fileStamp, toCsv, toJson } from "../utils/download";

function AttackTable({ events }) {

  const threats = events
    .filter((event) => event.intent === "prompt_injection")
    .slice(0, 10);

  const formatTime = (timestamp) => {
    if (!timestamp) return "-";

    return new Date(timestamp).toLocaleString();
  };

  const formatCategory = (category) => {
    if (!category) return "-";

    return category
      .replaceAll("_", " ")
      .replace(/\b\w/g, (char) => char.toUpperCase());
  };

  // ---- exports ------------------------------------------------------

  const exportAllCsv = () =>
    downloadText(
      `deep-deceiver-events_${fileStamp()}.csv`,
      toCsv(events),
      "text/csv"
    );

  const exportAllJson = () =>
    downloadText(
      `deep-deceiver-events_${fileStamp()}.json`,
      toJson(events),
      "application/json"
    );

  const exportRow = (event) =>
    downloadText(
      `deep-deceiver-event_${fileStamp(event.timestamp)}.json`,
      toJson(event),
      "application/json"
    );

  return (
    <div className="attack-table-container">

      <div className="section-header section-header-actions">
        <div>
          <h3>Recent Threats</h3>
          <p>Latest detected prompt injection events</p>
        </div>

        {events.length > 0 && (
          <div className="export-actions" role="group" aria-label="Export events">
            <Button
              variant="secondary"
              size="sm"
              icon={FileSpreadsheet}
              onClick={exportAllCsv}
              title={`Download all ${events.length} events in this time range as CSV`}
            >
              Download CSV
            </Button>

            <Button
              variant="secondary"
              size="sm"
              icon={FileJson}
              onClick={exportAllJson}
              title={`Download all ${events.length} events in this time range as JSON`}
            >
              Download JSON
            </Button>
          </div>
        )}
      </div>

      {threats.length === 0 ? (

        <div className="empty-state">
          No threats detected in the selected time range.
        </div>

      ) : (

        <div className="table-wrapper">

          <table className="attack-table">

            <thead>
              <tr>
                <th>Time</th>
                <th>Category</th>
                <th>Risk</th>
                <th>Route</th>
                <th>Action</th>
                <th>Download</th>
              </tr>
            </thead>

            <tbody>

              {threats.map((event, index) => (

                <tr key={`${event.session_id}-${index}`}>

                  <td>
                    {formatTime(event.timestamp)}
                  </td>

                  <td>
                    <span className="category-badge">
                      {formatCategory(event.attack_category)}
                    </span>
                  </td>

                  <td>
                    <span className="risk-value">
                      {(event.final_risk_score * 100).toFixed(1)}%
                    </span>
                  </td>

                  <td>
                    <span className="route-badge shadow">
                      {event.route}
                    </span>
                  </td>

                  <td>
                    <span className="action-badge">
                      {event.action}
                    </span>
                  </td>

                  <td>
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={Download}
                      onClick={() => exportRow(event)}
                      aria-label={`Download event from ${formatTime(event.timestamp)} as JSON`}
                    >
                      JSON
                    </Button>
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>

      )}

    </div>
  );
}

export default AttackTable;
