import React, { useEffect, useMemo } from "react";
import { useSelector } from "react-redux";
import { Link } from "react-router-dom";
import { fetchTargets } from "../../store/slices/targetsSlice";
import { useAppDispatch } from "../../hooks/useAppDispatch";
import type { RootState } from "../../store/store";
import type { Target } from "../../types";

interface OsGroup {
  os: string;
  targets: Target[];
  color: string;
}

const OS_COLORS: Record<string, string> = {
  windows: "#4fc3f7",
  linux: "#66bb6a",
  macos: "#ffa726",
  darwin: "#ffa726",
  unknown: "#888",
};

function getOsColor(os: string): string {
  const lower = os.toLowerCase();
  for (const [key, color] of Object.entries(OS_COLORS)) {
    if (lower.includes(key)) return color;
  }
  return OS_COLORS.unknown;
}

const Dashboard: React.FC = () => {
  const dispatch = useAppDispatch();
  const { list, status, error } = useSelector(
    (state: RootState) => state.targets
  );

  useEffect(() => {
    dispatch(fetchTargets());
  }, [dispatch]);

  const groups: OsGroup[] = useMemo(() => {
    const map = new Map<string, Target[]>();
    for (const t of list) {
      const key = t.status === "active" ? (t.os || "Unknown") : t.os || "Unknown";
      const arr = map.get(key) || [];
      arr.push(t);
      map.set(key, arr);
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1].length - a[1].length)
      .map(([os, targets]) => ({ os, targets, color: getOsColor(os) }));
  }, [list]);

  const maxCount = Math.max(1, ...groups.map((g) => g.targets.length));

  if (status === "loading") return <p>Loading dashboard...</p>;
  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Dashboard</h2>

      <div style={{ display: "flex", gap: "1.5rem", marginBottom: "2rem", flexWrap: "wrap" }}>
        <div className="stat-card">
          <span className="stat-value">{list.length}</span>
          <span className="stat-label">Total Targets</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{list.filter((t) => t.status === "active").length}</span>
          <span className="stat-label">Active</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{groups.length}</span>
          <span className="stat-label">OS Types</span>
        </div>
      </div>

      {list.length === 0 ? (
        <p>No targets connected.</p>
      ) : (
        <>
          <h3>Targets by Operating System</h3>
          <div className="chart-container">
            {groups.map((g) => (
              <div key={g.os} className="chart-row">
                <div className="chart-label">{g.os}</div>
                <div className="chart-bar-track">
                  <div
                    className="chart-bar"
                    style={{
                      width: `${(g.targets.length / maxCount) * 100}%`,
                      backgroundColor: g.color,
                    }}
                  >
                    <span className="chart-bar-count">{g.targets.length}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <h3 style={{ marginTop: "2rem" }}>Pivot: OS / IP Address</h3>
          <div className="pivot-wrapper">
            {groups.map((g) => (
              <div key={g.os} className="pivot-group">
                <div className="pivot-header" style={{ borderLeftColor: g.color }}>
                  {g.os}
                  <span className="pivot-badge" style={{ backgroundColor: g.color }}>
                    {g.targets.length}
                  </span>
                </div>
                <table className="pivot-table">
                  <thead>
                    <tr>
                      <th>Hostname</th>
                      <th>IP Address</th>
                      <th>Status</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {g.targets.map((t) => (
                      <tr key={t.id}>
                        <td>{t.hostname || "-"}</td>
                        <td style={{ fontFamily: "monospace" }}>{t.ip_address || "-"}</td>
                        <td>
                          <span
                            className="status-dot"
                            style={{
                              backgroundColor:
                                t.status === "active" ? "#66bb6a" : "#ef5350",
                            }}
                          />
                          {t.status}
                        </td>
                        <td>
                          <Link to={`/targets/${t.id}`}>View</Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

export default Dashboard;
