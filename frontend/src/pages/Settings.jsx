import React, { useCallback, useEffect, useRef, useState } from "react";

import { api, formatDate } from "../api.js";
import { Banner, Empty, Field, Modal, Spinner } from "../components.jsx";

const TABS = ["projects", "scanners", "scoring", "tokens", "backup"];
const METRICS = [
  ["E", "Exploit code maturity", ["X", "H", "F", "P", "U"]],
  ["RL", "Remediation level", ["X", "U", "W", "T", "O"]],
  ["RC", "Report confidence", ["X", "C", "R", "U"]],
  ["CR", "Confidentiality requirement", ["X", "H", "M", "L"]],
  ["IR", "Integrity requirement", ["X", "H", "M", "L"]],
  ["AR", "Availability requirement", ["X", "H", "M", "L"]],
  ["MAV", "Modified attack vector", ["X", "N", "A", "L", "P"]],
  ["MAC", "Modified attack complexity", ["X", "L", "H"]],
  ["MPR", "Modified privileges required", ["X", "N", "L", "H"]],
  ["MUI", "Modified user interaction", ["X", "N", "R"]],
  ["MS", "Modified scope", ["X", "U", "C"]],
  ["MC", "Modified confidentiality", ["X", "H", "L", "N"]],
  ["MI", "Modified integrity", ["X", "H", "L", "N"]],
  ["MA", "Modified availability", ["X", "H", "L", "N"]],
];

export default function Settings({ project, projects, reloadProjects, onError }) {
  const [tab, setTab] = useState("projects");
  const [notice, setNotice] = useState("");

  return (
    <div>
      <Banner kind="ok" onClose={() => setNotice("")}>
        {notice}
      </Banner>
      <div className="tabs">
        {TABS.map((item) => (
          <button key={item} className={`tab ${tab === item ? "active" : ""}`} onClick={() => setTab(item)}>
            {item}
          </button>
        ))}
      </div>

      {tab === "projects" && (
        <Projects projects={projects} reloadProjects={reloadProjects} onNotice={setNotice} onError={onError} />
      )}
      {tab === "scanners" && <Scanners project={project} onNotice={setNotice} onError={onError} />}
      {tab === "scoring" && <Scoring project={project} onNotice={setNotice} onError={onError} />}
      {tab === "tokens" && <Tokens projects={projects} onNotice={setNotice} onError={onError} />}
      {tab === "backup" && <Backup onNotice={setNotice} onError={onError} />}
    </div>
  );
}

function Projects({ projects, reloadProjects, onNotice, onError }) {
  const [editing, setEditing] = useState(null);

  const remove = async (item) => {
    if (!window.confirm(`Delete ${item.key} and its ${item.finding_count} findings?`)) return;
    try {
      await api.del(`/projects/${item.id}`);
      reloadProjects();
      onNotice(`${item.key} deleted`);
    } catch (exc) {
      onError(exc.message);
    }
  };

  return (
    <div>
      <div className="card">
        <div className="card-head">
          <h2 className="grow">Projects</h2>
          <button
            className="primary small"
            onClick={() =>
              setEditing({
                key: "",
                name: "",
                description: "",
                sla_critical: 7,
                sla_high: 30,
                sla_medium: 90,
                sla_low: 180,
                sla_info: 365,
              })
            }
          >
            new project
          </button>
        </div>
        {projects.length === 0 ? (
          <Empty title="No project yet">
            A project is the only grouping level. Its key shows up in report filenames and in
            conversations, keep it short: BACKEND, SATVIS, PAYMENTS.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>Name</th>
                <th className="right">Findings</th>
                <th className="right">Open</th>
                <th>SLA days (C / H / M / L / I)</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {projects.map((item) => (
                <tr key={item.id}>
                  <td className="ref">{item.key}</td>
                  <td>{item.name}</td>
                  <td className="right">{item.finding_count}</td>
                  <td className="right">{item.open_count}</td>
                  <td className="mono">
                    {item.sla_critical} / {item.sla_high} / {item.sla_medium} / {item.sla_low} / {item.sla_info}
                  </td>
                  <td>
                    <div className="row tight">
                      <button className="small" onClick={() => setEditing(item)}>
                        edit
                      </button>
                      <button className="small danger" onClick={() => remove(item)}>
                        delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {editing && (
        <ProjectForm
          value={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            reloadProjects();
            onNotice("project saved");
          }}
          onError={onError}
        />
      )}
    </div>
  );
}

function ProjectForm({ value, onClose, onSaved, onError }) {
  const [draft, setDraft] = useState(value);

  const submit = async () => {
    const payload = {
      key: draft.key,
      name: draft.name,
      description: draft.description || "",
      sla_critical: Number(draft.sla_critical),
      sla_high: Number(draft.sla_high),
      sla_medium: Number(draft.sla_medium),
      sla_low: Number(draft.sla_low),
      sla_info: Number(draft.sla_info),
    };
    try {
      if (draft.id) await api.put(`/projects/${draft.id}`, payload);
      else await api.post("/projects", payload);
      onSaved();
    } catch (exc) {
      onError(exc.message);
    }
  };

  return (
    <Modal title={draft.id ? `Edit ${draft.key}` : "New project"} onClose={onClose}>
      <div className="grid cols-2">
        <Field label="Key" hint="used in filenames and reports">
          <input value={draft.key} onChange={(event) => setDraft({ ...draft, key: event.target.value })} />
        </Field>
        <Field label="Name">
          <input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} />
        </Field>
      </div>
      <Field label="Description">
        <textarea
          value={draft.description || ""}
          onChange={(event) => setDraft({ ...draft, description: event.target.value })}
        />
      </Field>
      <h3 style={{ margin: "12px 0 8px" }}>SLA window in days</h3>
      <div className="grid cols-5">
        {["critical", "high", "medium", "low", "info"].map((level) => (
          <Field key={level} label={level}>
            <input
              type="number"
              min="1"
              value={draft[`sla_${level}`]}
              onChange={(event) => setDraft({ ...draft, [`sla_${level}`]: event.target.value })}
            />
          </Field>
        ))}
      </div>
      <button className="primary" disabled={!draft.key || !draft.name} onClick={submit}>
        save
      </button>
    </Modal>
  );
}

function Scanners({ project, onNotice, onError }) {
  const [adapters, setAdapters] = useState([]);
  const [configs, setConfigs] = useState([]);
  const [editing, setEditing] = useState(null);

  const load = useCallback(async () => {
    try {
      setAdapters(await api.get("/scanners/adapters"));
      setConfigs(await api.get("/scanners/configs"));
    } catch (exc) {
      onError(exc.message);
    }
  }, [onError]);

  useEffect(() => {
    load();
  }, [load]);

  const test = async (config) => {
    try {
      const result = await api.post(`/scanners/configs/${config.id}/test`);
      onNotice(`${config.name}: ${result.message}`);
    } catch (exc) {
      onError(exc.message);
    }
  };

  const remove = async (config) => {
    await api.del(`/scanners/configs/${config.id}`);
    load();
  };

  return (
    <div>
      <div className="card">
        <h2>Adapters shipped with this build</h2>
        <p className="muted" style={{ marginTop: 4 }}>
          One adapter is one file under <span className="mono">backend/vulncano/adapters/</span>. The
          form below is generated from each adapter's config schema, so adding a scanner never touches
          the frontend.
        </p>
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Kind</th>
              <th>Accepts</th>
              <th>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {adapters.map((adapter) => (
              <tr key={adapter.tool}>
                <td>
                  <strong>{adapter.label}</strong>
                  <div className="mono muted">{adapter.tool}</div>
                </td>
                <td className="muted">{adapter.is_importer ? "importer" : "scanner"}</td>
                <td className="muted truncate" style={{ maxWidth: 300 }}>
                  {adapter.accepts.join(", ")}
                </td>
                <td>
                  {adapter.implemented ? (
                    <span className="pill ok">ready</span>
                  ) : (
                    <span className="pill ember">under development</span>
                  )}
                </td>
                <td>
                  {adapter.needs_credentials && (
                    <button
                      className="small"
                      onClick={() =>
                        setEditing({ tool: adapter.tool, name: adapter.label, config: {}, project_id: null })
                      }
                    >
                      add credentials
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h2>Saved scanner configurations</h2>
        {configs.length === 0 ? (
          <Empty title="Nothing configured">
            OSV.dev and every importer work without any configuration at all.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Tool</th>
                <th>Scope</th>
                <th>Credentials</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {configs.map((config) => (
                <tr key={config.id}>
                  <td>{config.name}</td>
                  <td className="mono">{config.tool}</td>
                  <td className="muted">{config.project_id ? `project ${config.project_id}` : "global"}</td>
                  <td>
                    {config.credential_set ? (
                      <span className="pill ok">set</span>
                    ) : (
                      <span className="pill">none</span>
                    )}
                  </td>
                  <td>
                    <div className="row tight">
                      <button className="small" onClick={() => test(config)}>
                        test
                      </button>
                      <button className="small" onClick={() => setEditing(config)}>
                        edit
                      </button>
                      <button className="small danger" onClick={() => remove(config)}>
                        delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {editing && (
        <ScannerForm
          value={editing}
          adapter={adapters.find((item) => item.tool === editing.tool)}
          project={project}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load();
            onNotice("scanner configuration saved");
          }}
          onError={onError}
        />
      )}
    </div>
  );
}

function ScannerForm({ value, adapter, project, onClose, onSaved, onError }) {
  const [draft, setDraft] = useState({ ...value, config: { ...value.config } });
  const properties = adapter && adapter.schema ? adapter.schema.properties || {} : {};

  const submit = async () => {
    const payload = {
      tool: draft.tool,
      name: draft.name,
      enabled: draft.enabled !== false,
      project_id: draft.project_id || null,
      config: draft.config,
    };
    try {
      if (draft.id) await api.put(`/scanners/configs/${draft.id}`, payload);
      else await api.post("/scanners/configs", payload);
      onSaved();
    } catch (exc) {
      onError(exc.message);
    }
  };

  return (
    <Modal title={`${adapter ? adapter.label : draft.tool} credentials`} onClose={onClose}>
      {adapter && !adapter.implemented && (
        <Banner kind="error">
          This adapter cannot run yet. The credentials are stored and the form is the real one, so the
          contribution that finishes it needs no UI work.
        </Banner>
      )}
      <Field label="Name">
        <input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} />
      </Field>
      <Field label="Scope">
        <select
          value={draft.project_id || ""}
          onChange={(event) => setDraft({ ...draft, project_id: event.target.value ? Number(event.target.value) : null })}
        >
          <option value="">global, every project</option>
          {project && <option value={project.id}>only {project.key}</option>}
        </select>
      </Field>
      {Object.entries(properties).map(([name, spec]) => {
        const secret = Boolean(spec.secret);
        return (
          <Field key={name} label={name} hint={spec.description}>
            {spec.type === "boolean" ? (
              <input
                type="checkbox"
                checked={Boolean(draft.config[name])}
                onChange={(event) => setDraft({ ...draft, config: { ...draft.config, [name]: event.target.checked } })}
              />
            ) : (
              <input
                type={secret ? "password" : "text"}
                placeholder={secret && value.credential_set ? "stored, leave empty to keep it" : String(spec.default ?? "")}
                value={draft.config[name] ?? ""}
                onChange={(event) => setDraft({ ...draft, config: { ...draft.config, [name]: event.target.value } })}
              />
            )}
          </Field>
        );
      })}
      <p className="muted" style={{ fontSize: 12 }}>
        Secrets are encrypted with VULNCANO_SECRET_KEY and never come back out of the API.
      </p>
      <button className="primary" onClick={submit}>
        save
      </button>
    </Modal>
  );
}

function Scoring({ project, onNotice, onError }) {
  const [metrics, setMetrics] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!project) return;
    api.get(`/cvss/project/${project.id}`).then(setMetrics).catch((exc) => onError(exc.message));
  }, [project, onError]);

  if (!project) return <Empty title="Pick a project first" />;
  if (!metrics) return <Spinner label="loading" />;

  const save = async () => {
    setBusy(true);
    try {
      const result = await api.put(`/cvss/project/${project.id}`, metrics);
      onNotice(`${result.recomputed} findings recomputed with the new metrics`);
    } catch (exc) {
      onError(exc.message);
    } finally {
      setBusy(false);
    }
  };

  const refresh = async () => {
    setBusy(true);
    try {
      const result = await api.post(`/cvss/refresh?project_id=${project.id}&limit=50`);
      onNotice(
        `${result.updated} findings scored from the NVD` +
          (result.failed.length ? `, ${result.failed.length} failed: ${result.failed[0]}` : "")
      );
    } catch (exc) {
      onError(exc.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="card">
        <h2>Temporal and environmental metrics for {project.key}</h2>
        <p className="muted" style={{ marginTop: 4 }}>
          These sit on top of the base vector and produce the adapted score, which is the number the
          team prioritises with. Saving recomputes every finding in the project. A per finding
          override wins over what is set here.
        </p>
        <div className="grid cols-3">
          {METRICS.map(([key, label, values]) => (
            <Field key={key} label={`${key} · ${label}`}>
              <select value={metrics[key]} onChange={(event) => setMetrics({ ...metrics, [key]: event.target.value })}>
                {values.map((value) => (
                  <option key={value} value={value}>
                    {value === "X" ? "X (not defined)" : value}
                  </option>
                ))}
              </select>
            </Field>
          ))}
        </div>
        <div className="row">
          <button className="primary" disabled={busy} onClick={save}>
            save and recompute
          </button>
          <button disabled={busy} onClick={refresh}>
            fetch missing base scores from the NVD
          </button>
          {busy && <Spinner />}
        </div>
      </div>
    </div>
  );
}

function Tokens({ projects, onNotice, onError }) {
  const [tokens, setTokens] = useState([]);
  const [fresh, setFresh] = useState(null);
  const [draft, setDraft] = useState({ name: "", project_id: "" });

  const load = useCallback(async () => {
    try {
      setTokens(await api.get("/tokens"));
    } catch (exc) {
      onError(exc.message);
    }
  }, [onError]);

  useEffect(() => {
    load();
  }, [load]);

  const create = async () => {
    try {
      const token = await api.post("/tokens", {
        name: draft.name,
        project_id: draft.project_id ? Number(draft.project_id) : null,
      });
      setFresh(token.token);
      setDraft({ name: "", project_id: "" });
      load();
    } catch (exc) {
      onError(exc.message);
    }
  };

  const revoke = async (token) => {
    await api.del(`/tokens/${token.id}`);
    onNotice(`${token.prefix}… revoked`);
    load();
  };

  return (
    <div>
      <div className="card">
        <h2>API tokens for CI</h2>
        <p className="muted" style={{ marginTop: 4 }}>
          A build pushes its scanner output to <span className="mono">POST /api/findings/ingest</span>.
          Rows arriving that way are stamped with the job identifier and land as New, never
          overwriting a triage decision.
        </p>
        <div className="row">
          <input
            style={{ width: 220 }}
            placeholder="token name"
            value={draft.name}
            onChange={(event) => setDraft({ ...draft, name: event.target.value })}
          />
          <select
            style={{ width: 220 }}
            value={draft.project_id}
            onChange={(event) => setDraft({ ...draft, project_id: event.target.value })}
          >
            <option value="">not scoped to a project</option>
            {projects.map((item) => (
              <option key={item.id} value={item.id}>
                {item.key}
              </option>
            ))}
          </select>
          <button className="primary" disabled={!draft.name} onClick={create}>
            create token
          </button>
        </div>
        {fresh && (
          <div className="banner ok" style={{ marginTop: 12 }}>
            <div>Copy it now, it is not shown again.</div>
            <div className="log" style={{ marginTop: 6 }}>{fresh}</div>
          </div>
        )}
      </div>

      <div className="card">
        {tokens.length === 0 ? (
          <Empty title="No token yet" />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Prefix</th>
                <th>Project</th>
                <th>Last used</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <tr key={token.id} className={token.revoked_at ? "resolved" : ""}>
                  <td>{token.name}</td>
                  <td className="mono">{token.prefix}…</td>
                  <td className="muted">{token.project_id || "any"}</td>
                  <td className="muted">{formatDate(token.last_used_at)}</td>
                  <td>{token.revoked_at ? <span className="pill bad">revoked</span> : <span className="pill ok">active</span>}</td>
                  <td>
                    {!token.revoked_at && (
                      <button className="small danger" onClick={() => revoke(token)}>
                        revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Backup({ onNotice, onError }) {
  const input = useRef(null);

  const restore = async (file) => {
    if (!window.confirm("Restoring replaces everything currently stored. Continue?")) return;
    const form = new FormData();
    form.append("file", file);
    try {
      const result = await api.upload("/dump/restore", form);
      onNotice(`${result.statements} rows restored, reload the page`);
    } catch (exc) {
      onError(exc.message);
    }
  };

  return (
    <div className="card">
      <h2>Backup</h2>
      <p className="muted" style={{ marginTop: 4 }}>
        The dump is plain SQL, portable between SQLite and MySQL. The same thing from the shell:{" "}
        <span className="mono">vulncano dump --out backup.sql</span>.
      </p>
      <div className="row">
        <button className="primary" onClick={() => api.download("/dump")}>
          download SQL dump
        </button>
        <button onClick={() => input.current.click()}>restore from a dump</button>
        <input
          ref={input}
          type="file"
          accept=".sql"
          style={{ display: "none" }}
          onChange={(event) => event.target.files[0] && restore(event.target.files[0])}
        />
      </div>
    </div>
  );
}
