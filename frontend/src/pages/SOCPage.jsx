
import { useEffect, useState } from "react";

import { authHeaders } from "../api";
import ThreatSummary from "../components/ThreatSummary";
import AttackTable from "../components/AttackTable";

function SOCPage() {

  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchSOCData = async () => {

    try {

      setLoading(true);
      setError("");

      const [statsResponse, eventsResponse] = await Promise.all([
        fetch("http://127.0.0.1:8000/soc/stats", { headers: authHeaders() }),
        fetch("http://127.0.0.1:8000/soc/events", { headers: authHeaders() })
      ]);

      if (!statsResponse.ok || !eventsResponse.ok) {
        throw new Error("Failed to fetch SOC data.");
      }

      const statsData = await statsResponse.json();
      const eventsData = await eventsResponse.json();

      setStats(statsData);
      setEvents(eventsData.events);

    } catch (error) {

      console.error(error);

      setError(
        "Unable to load SOC data. Make sure the backend and InfluxDB are running."
      );

    } finally {

      setLoading(false);

    }
  };

  useEffect(() => {
    const first = setTimeout(fetchSOCData, 0);

    return () => clearTimeout(first);
  }, []);

  if (loading) {

    return (
      <main className="soc-container">
        <div className="soc-loading">
          Loading SOC data...
        </div>
      </main>
    );

  }

  if (error) {

    return (
      <main className="soc-container">

        <div className="soc-error">
          <h2>SOC Dashboard</h2>

          <p>{error}</p>

          <button
            className="refresh-button"
            onClick={fetchSOCData}
          >
            Retry
          </button>

        </div>

      </main>
    );

  }

  return (
    <main className="soc-container">

      {/* HEADER */}
      <div className="soc-header">

        <div>

          <h2>DEEP-DECEIVER SOC</h2>

          <p>
            Security Operations Center
          </p>

        </div>

        <button
          className="refresh-button"
          onClick={fetchSOCData}
        >
          Refresh
        </button>

      </div>


      {/* SUMMARY */}
      <ThreatSummary stats={stats} />


      {/* ATTACK CATEGORIES */}
      <section className="soc-section">

        <div className="section-header">

          <div>

            <h3>Attack Categories</h3>

            <p>
              Distribution of events processed by the defense pipeline
            </p>

          </div>

        </div>


        <div className="category-list">

          {Object.entries(
            stats.attack_categories || {}
          ).map(
            ([category, count]) => {

              const percentage =
                stats.total_events > 0
                  ? (count / stats.total_events) * 100
                  : 0;

              return (
                <div
                  className="category-row"
                  key={category}
                >

                  <div className="category-name">

                    {category
                      .replaceAll("_", " ")
                      .replace(/\b\w/g, (char) =>
                        char.toUpperCase()
                      )}

                  </div>


                  <div className="category-bar-container">

                    <div
                      className="category-bar"
                      style={{
                        width: `${percentage}%`
                      }}
                    />

                  </div>


                  <div className="category-count">
                    {count}
                  </div>

                </div>
              );

            }
          )}

        </div>

      </section>


      {/* KILL CHAIN */}
      <section className="soc-section">

        <div className="section-header">

          <div>

            <h3>Kill Chain Activity</h3>

            <p>
              Observed attacker progression across sessions
            </p>

          </div>

        </div>


        <div className="category-list">

          {Object.entries(
            stats.kill_chain_stages || {}
          ).map(
            ([stage, count]) => {

              const percentage =
                stats.total_events > 0
                  ? (count / stats.total_events) * 100
                  : 0;

              return (
                <div
                  className="category-row"
                  key={stage}
                >

                  <div className="category-name">

                    {stage
                      .replaceAll("_", " ")
                      .replace(/\b\w/g, (char) =>
                        char.toUpperCase()
                      )}

                  </div>


                  <div className="category-bar-container">

                    <div
                      className="category-bar"
                      style={{
                        width: `${percentage}%`
                      }}
                    />

                  </div>


                  <div className="category-count">
                    {count}
                  </div>

                </div>
              );

            }
          )}

        </div>

      </section>


      {/* MITRE ATLAS */}
      <section className="soc-section">

        <div className="section-header">

          <div>

            <h3>MITRE ATLAS Techniques</h3>

            <p>
              Attack techniques identified by the defense pipeline
            </p>

          </div>

        </div>


        <div className="category-list">

          {Object.entries(
            stats.mitre_techniques || {}
          ).map(
            ([technique, count]) => {

              const percentage =
                stats.total_events > 0
                  ? (count / stats.total_events) * 100
                  : 0;

              return (
                <div
                  className="category-row"
                  key={technique}
                >

                  <div className="category-name">
                    {technique}
                  </div>


                  <div className="category-bar-container">

                    <div
                      className="category-bar"
                      style={{
                        width: `${percentage}%`
                      }}
                    />

                  </div>


                  <div className="category-count">
                    {count}
                  </div>

                </div>
              );

            }
          )}

        </div>

      </section>


      {/* ATTACK TABLE */}
      <section className="soc-section">

        <AttackTable events={events} />

      </section>

    </main>
  );
}

export default SOCPage;
