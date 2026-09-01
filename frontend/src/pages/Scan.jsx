import React, { useEffect, useRef, useState } from "react";

import { api, formatScore } from "../api.js";
import { Banner, Empty, Field, Modal, Spinner } from "../components.jsx";

const POLL_MS = 1200;

export default function Scan({ project, projects, meta, navigate, onError }) {
  const [adapters, setAdapters] = useState([]);
  const [configs, setConfigs] = useState([]);
  const [tool, setTool] = useState("osv");
  const [configId, setConfigId] = useState("");
  const [files, setFiles] = useState([]);
  const [image, setImage] = useState("");
  const [path, setPath] = useState("");
  const [scan, setScan] = useState(null);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [blocked, setBlocked] = useState(null);
  const timer = useRef(null);

  useEffect(() => {
    api.get("/scanners/adapters").then(setAdapters).catch((exc) => onError(exc.message));
  }, [onError]);

  useEffect(() => {
    if (!project) return;
    api.get("/scanners/configs", { project_id: project.id }).then(setConfigs).catch(() => {});
  }, [project]);

  useEffect(() => () => clearTimeout(timer.current), []);

  const adapter = adapters.find((item) => item.tool === tool);
  const importers = adapters.filter((item) => item.is_importer);
  const scanners = adapters.filter((item) => !item.is_importer);
  const usable = configs.filter((item) => item.tool === tool);

  const poll = async (scanId) => {
    try {
      const current = await api.get(`/scans/${scanId}`);
      setScan(current);
      if (current.status === "parsed" || current.status === "imported") {
        const results = await api.get(`/scans/${scanId}/results`);
        setPreview(results);
        setBusy(false);
        return;
      }
      if (current.status === "failed") {
        setBusy(false);
        return;
      }
      timer.current = setTimeout(() => poll(scanId), POLL_MS);
    } catch (exc) {
      setBusy(false);
      onError(exc.message);
    }
  };

  const launch = async () => {
    if (adapter && !adapter.implemented) {
      setBlocked(adapter);
      return;
    }
    setBusy(true);
    setPreview(null);
    setScan(null);
    const form = new FormData();
    form.append("project_id", project.id);
    form.append("tool", tool);
    if (configId) form.append("scanner_config_id", configId);
    if (image) form.append("image", image);
    if (path) form.append("path", path);
    files.forEach((file) => form.append("files", file));
    try {
      const created = await api.upload("/scans", form);
      setScan(created);
      poll(created.id);
    } catch (exc) {
      setBusy(false);
      if (exc.underDevelopment) setBlocked(adapter);
      else onError(exc.message);
    }
  };

  const importFiles = async () => {
    setBusy(true);
    setPreview(null);
    setScan(null);
    const form = new FormData();
    form.append("project_id", project.id);
    files.forEach((file) => form.append("files", file));
    try {
      setPreview(await api.upload("/findings/preview", form));
    } catch (exc) {
      onError(exc.message);
    } finally {
      setBusy(false);
    }
  };

  if (!project) return null;

  return (
    <div>
      <Banner kind="ok" onClose={() => setNotice("")}>
        {notice}
      </Banner>

      <div className="grid cols-2">
        <div className="card">
          <h2>Run a scanner</h2>
          <p className="muted" style={{ marginTop: 4 }}>
            OSV.dev works with no credentials at all. Give it a dependency manifest and it answers in
            a few seconds.
          </p>
          <Field label="Scanner">
            <select value={tool} onChange={(event) => setTool(event.target.value)}>
              {scanners.map((item) => (
                <option key={item.tool} value={item.tool}>
                  {item.label}
                  {item.implemented ? "" : " (under development)"}
                </option>
              ))}
            </select>
          </Field>
          {adapter && adapter.needs_credentials && (
            <Field label="Credentials" hint="configured under Settings">
              <select value={configId} onChange={(event) => setConfigId(event.target.value)}>
                <option value="">none, use the defaults</option>
                {usable.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                    {item.credential_set ? " ✓" : ""}
                  </option>
                ))}
              </select>
            </Field>
          )}
          <FilePicker files={files} setFiles={setFiles} hint={adapter ? adapter.accepts.join(", ") : ""} />
          <div className="grid cols-2">
            <Field label="or a container image">
              <input placeholder="python:3.9-slim" value={image} onChange={(event) => setImage(event.target.value)} />
            </Field>
            <Field label="or a path on the server">
              <input placeholder="/srv/checkouts/backend" value={path} onChange={(event) => setPath(event.target.value)} />
            </Field>
          </div>
          <button className="primary" disabled={busy} onClick={launch}>
            {busy ? <Spinner label="scanning" /> : "run scan"}
          </button>
          {adapter && !adapter.implemented && (
            <p className="muted" style={{ marginTop: 10 }}>
              This adapter is a contribution target. Its configuration form and result parser are in
              place, the launch step is not.
            </p>
          )}
        </div>

        <div className="card">
          <h2>Import a report you already have</h2>
          <p className="muted" style={{ marginTop: 4 }}>
            The format is detected from the file: {importers.map((item) => item.label).join(", ")}. Drop
            several files at once, each row keeps the project taken from its filename when it matches a
            project key.
          </p>
          <FilePicker files={files} setFiles={setFiles} hint="sarif, cyclonedx, grype, dependency-check, csv" />
          <button disabled={busy || files.length === 0} onClick={importFiles}>
            {busy ? <Spinner label="parsing" /> : "parse into a preview"}
          </button>
          <div className="row" style={{ marginTop: 14 }}>
            <span className="muted">Manifests understood by every dependency scanner:</span>
          </div>
          <div className="row tight" style={{ marginTop: 6 }}>
            {(meta.manifests || []).map((item) => (
              <span key={item} className="pill">
                {item}
              </span>
            ))}
          </div>
        </div>
      </div>

      {scan && (
        <div className="card">
          <div className="card-head">
            <h2 className="grow">
              {scan.ref} · {scan.tool}
            </h2>
            <span className={`pill ${scan.status === "failed" ? "bad" : scan.status === "parsed" ? "ok" : ""}`}>
              {scan.status}
            </span>
          </div>
          {scan.error && <Banner kind="error">{scan.error}</Banner>}
          <div className="log">{scan.log || "waiting for the scanner…"}</div>
        </div>
      )}

      {preview && (
        <Preview
          preview={preview}
          setPreview={setPreview}
          project={project}
          projects={projects}
          meta={meta}
          onImported={(result) => {
            setPreview(null);
            setFiles([]);
            setNotice(
              `${result.created.length} findings imported (${result.created.join(", ")})` +
                (result.plan_ref ? `, plan ${result.plan_ref} created` : "")
            );
            navigate("findings");
          }}
          onError={onError}
        />
      )}

      {blocked && (
        <Modal title={`${blocked.label} is under development`} onClose={() => setBlocked(null)}>
          <p>
            The adapter interface, the settings form and the result parser for {blocked.label} ship
            with Vulncano, but the step that launches it does not run yet.
          </p>
          <p className="muted">{blocked.install_hint}</p>
          <p>
            In the meantime, run {blocked.label} yourself and import its output on the right hand side
            of this screen. Finishing this adapter is one file:{" "}
            <span className="mono">backend/vulncano/adapters/{blocked.tool}.py</span>.
          </p>
          <div className="row">
            <a
              className="btn"
              href={`https://github.com/storesm/vulncano/blob/main/backend/vulncano/adapters/${blocked.tool}.py`}
              target="_blank"
              rel="noreferrer"
            >
              read the adapter
            </a>
            <button onClick={() => setBlocked(null)}>close</button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function FilePicker({ files, setFiles, hint }) {
  const [over, setOver] = useState(false);
  const input = useRef(null);

  const add = (list) => setFiles([...files, ...Array.from(list)]);

  return (
    <div>
      <div
        className={`dropzone ${over ? "over" : ""}`}
        onClick={() => input.current.click()}
        onDragOver={(event) => {
          event.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(event) => {
          event.preventDefault();
          setOver(false);
          add(event.dataTransfer.files);
        }}
      >
        <strong>drop files here</strong> or click to choose
        {hint ? <div style={{ fontSize: 12, marginTop: 4 }}>{hint}</div> : null}
      </div>
      <input
        ref={input}
        type="file"
        multiple
        style={{ display: "none" }}
        onChange={(event) => add(event.target.files)}
      />
      {files.length > 0 && (
        <div className="row tight" style={{ margin: "10px 0" }}>
          {files.map((file, index) => (
            <span key={`${file.name}-${index}`} className="pill ember">
              {file.name}
              <button
                className="ghost small"
                style={{ padding: "0 4px", border: "none" }}
                onClick={() => setFiles(files.filter((_, position) => position !== index))}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function Preview({ preview, setPreview, project, projects, meta, onImported, onError }) {
  const [patch, setPatch] = useState({ fixed_version: "", regression_tests: "", schedule: "" });
  const [plan, setPlan] = useState({ name: "", target_version: "", target_date: "" });
  const [attachPatch, setAttachPatch] = useState(false);
  const [attachPlan, setAttachPlan] = useState(false);
  const [busy, setBusy] = useState(false);

  const rows = preview.rows;
  const included = rows.filter((row) => row.include);

  const update = (index, changes) => {
    const next = rows.map((row, position) => (position === index ? { ...row, ...changes } : row));
    let counter = preview.next_number;
    next.forEach((row) => {
      row.suggested_ref = row.include ? `VLN-${String(counter++).padStart(4, "0")}` : "";
    });
    setPreview({ ...preview, rows: next });
  };

  const submit = async () => {
    setBusy(true);
    try {
      const result = await api.post("/findings/import", {
        scan_id: preview.scan_id,
        rows,
        patch: attachPatch ? patch : null,
        plan: attachPlan ? { project_id: project.id, ...plan, target_date: plan.target_date || null } : null,
      });
      onImported(result);
    } catch (exc) {
      onError(exc.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <h2 className="grow">
          Preview · {included.length} of {rows.length} rows will be stored
        </h2>
        <span className="muted">{preview.duplicate_count} duplicates unticked</span>
      </div>

      {preview.warnings.length > 0 && (
        <div className="log" style={{ marginBottom: 12, maxHeight: 120 }}>
          {preview.warnings.join("\n")}
        </div>
      )}

      {rows.length === 0 ? (
        <Empty title="Nothing came back">The scanner found no vulnerabilities in this target.</Empty>
      ) : (
        <div className="scroll-x">
          <table className="preview-table">
            <thead>
              <tr>
                <th style={{ width: 28 }} />
                <th>Id</th>
                <th>CVE</th>
                <th>Severity</th>
                <th className="right">Score</th>
                <th>Components</th>
                <th>Type</th>
                <th>Status</th>
                <th>Project</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr
                  key={index}
                  className={`${row.include ? "" : "skipped"} ${row.regression_of ? "regression" : ""}`}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={row.include}
                      onChange={(event) => update(index, { include: event.target.checked })}
                    />
                  </td>
                  <td className="ref">{row.suggested_ref || "—"}</td>
                  <td className="ref">{row.cve_id || row.external_id || "—"}</td>
                  <td>
                    <select
                      value={row.severity}
                      onChange={(event) => update(index, { severity: event.target.value })}
                    >
                      {meta.severities.map((item) => (
                        <option key={item}>{item}</option>
                      ))}
                    </select>
                  </td>
                  <td className="right mono">{formatScore(row.adapted_score ?? row.cvss_base_score)}</td>
                  <td>
                    <textarea
                      rows={Math.min(3, (row.components || "").split("\n").length)}
                      style={{ minHeight: 26, width: 240 }}
                      value={row.components}
                      onChange={(event) => update(index, { components: event.target.value })}
                    />
                  </td>
                  <td>
                    <select
                      value={row.scan_type}
                      onChange={(event) => update(index, { scan_type: event.target.value })}
                    >
                      {meta.scan_types.map((item) => (
                        <option key={item}>{item}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select value={row.status} onChange={(event) => update(index, { status: event.target.value })}>
                      {meta.statuses.map((item) => (
                        <option key={item}>{item}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select
                      value={row.project_id}
                      onChange={(event) => update(index, { project_id: Number(event.target.value) })}
                    >
                      {projects.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.key}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="muted" style={{ maxWidth: 220, fontSize: 12 }}>
                    {row.regression_of ? (
                      <span className="pill bad">regression of {row.regression_of}</span>
                    ) : (
                      row.duplicate_reason
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <div>
          <label className="row tight">
            <input type="checkbox" checked={attachPatch} onChange={(event) => setAttachPatch(event.target.checked)} />
            <strong>attach one patch to every imported row</strong>
          </label>
          {attachPatch && (
            <div style={{ marginTop: 8 }}>
              <Field label="Fixed version">
                <input
                  value={patch.fixed_version}
                  onChange={(event) => setPatch({ ...patch, fixed_version: event.target.value })}
                />
              </Field>
              <Field label="Regression tests">
                <input
                  value={patch.regression_tests}
                  onChange={(event) => setPatch({ ...patch, regression_tests: event.target.value })}
                />
              </Field>
              <Field label="Schedule">
                <input
                  value={patch.schedule}
                  onChange={(event) => setPatch({ ...patch, schedule: event.target.value })}
                />
              </Field>
            </div>
          )}
        </div>
        <div>
          <label className="row tight">
            <input type="checkbox" checked={attachPlan} onChange={(event) => setAttachPlan(event.target.checked)} />
            <strong>group them into one remediation plan</strong>
          </label>
          {attachPlan && (
            <div style={{ marginTop: 8 }}>
              <Field label="Plan name">
                <input value={plan.name} onChange={(event) => setPlan({ ...plan, name: event.target.value })} />
              </Field>
              <Field label="Target version">
                <input
                  value={plan.target_version}
                  onChange={(event) => setPlan({ ...plan, target_version: event.target.value })}
                />
              </Field>
              <Field label="Target date">
                <input
                  type="date"
                  value={plan.target_date}
                  onChange={(event) => setPlan({ ...plan, target_date: event.target.value })}
                />
              </Field>
            </div>
          )}
        </div>
      </div>

      <div className="row" style={{ marginTop: 16 }}>
        <button className="primary" disabled={busy || included.length === 0} onClick={submit}>
          {busy ? <Spinner label="importing" /> : `import ${included.length} findings`}
        </button>
        <button className="ghost" onClick={() => setPreview(null)}>
          discard
        </button>
        <span className="muted">Nothing has been written yet.</span>
      </div>
    </div>
  );
}
