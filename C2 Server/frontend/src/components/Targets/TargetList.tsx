import React, { useEffect } from "react";
import { useSelector } from "react-redux";
import { fetchTargets, toggleTargetStatus } from "../../store/slices/targetsSlice";
import { useAppDispatch } from "../../hooks/useAppDispatch";
import { Link } from "react-router-dom";
import type { RootState } from "../../store/store";

const TargetList: React.FC = () => {
  const dispatch = useAppDispatch();
  const { list, status, error } = useSelector((state: RootState) => state.targets);

  useEffect(() => {
    dispatch(fetchTargets());
  }, [dispatch]);

  if (status === "loading") return <p>Loading targets...</p>;
  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Targets</h2>
      {list.length === 0 ? (
        <p>No targets connected.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Hostname</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map((target) => (
              <tr key={target.id}>
                <td>{target.id}</td>
                <td>{target.hostname}</td>
                <td>{target.ip_address}</td>
                <td style={{ color: target.status === "active" ? "#66bb6a" : "#ef5350" }}>
                  {target.status}
                </td>
                <td style={{ display: "flex", gap: "0.5rem" }}>
                  <Link to={`/targets/${target.id}`}>View</Link>
                  <button
                    className="btn-secondary"
                    onClick={() =>
                      dispatch(
                        toggleTargetStatus({
                          targetId: target.id,
                          newStatus: target.status === "inactive" ? "active" : "inactive",
                        })
                      )
                    }
                    style={{ padding: "0.15rem 0.5rem", fontSize: "0.75rem" }}
                  >
                    {target.status === "inactive" ? "Activate" : "Deactivate"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default TargetList;
