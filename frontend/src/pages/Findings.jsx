import React, { useCallback, useEffect, useMemo, useState } from "react";

import { api, formatDate, formatScore } from "../api.js";
import { Banner, Drawer, Empty, Field, Modal, Spinner } from "../components.jsx";

const CLOSED = ["Fixed", "False positive", "Risk accepted"];
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

function rowClass(finding, selected) {
  const parts = [];
  if (CLOSED.includes(finding.status)) parts.push("resolved");
  else parts.push(finding.status === "New" ? "state-new" : "state-confirmed");
  if (selected) parts.push("selected");
  return parts.join(" ");
}

export default function Findings({ project, meta, argument, navigate, onError }) {
  const [filters, setFilters] = useState({
    severity: "",
    status: "",
    tool: "",
    scan_type: "",
    reported: "",
    has_patch: "",
    has_plan: "",
    q: "",
  });
  const [sort, setSort] = useState({ column: "severity", order: "desc" });
  const [page, setPage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState([]);
  const [open, setOpen] = useState(null);
  const [planModal, setPlanModal] = useState(false);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    if (!project) return;
    setLoading(true);
    try {
      const data = await api.get("/findings", {
        project_id: project.id,
        ...filters,
        sort: sort.column,
        order: sort.order,
        limit: 300,
      });
      setPage(data);
    } catch (exc) {
      onError(exc.message);
    } finally {
      setLoading(false);
    }
  }, [project, filters, sort, onError]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    setSelected([]);
  }, [project]);

  useEffect(() => {
    if (argument && page) {
      const match = page.items.find((item) => item.ref === argument);
      if (match) setOpen(match);
    }
  }, [argument, page]);

  const items = page ? page.items : [];
  const tools = useMemo(() => [...new Set(items.map((item) => item.tool).filter(Boolean))], [items]);
  const allSelected = items.length > 0 && selected.length === items.length;

  const toggle = (id) =>
    setSelected((current) => (current.includes(id) ? current.filter((item) => item !== id) : [...current, id]));

  const bulk = async (payload) => {
    try {
      await api.post("/findings/batch-update", { ids: selected, ...payload });
      setMessage(`${selected.length} findings updated`);
      setSelected([]);
      load();
    } catch (exc) {
      onError(exc.message);
    }
  };

  const removeSelected = async () => {
    if (!window.confirm(`Delete ${selected.length} findings? This cannot be undone.`)) return;
    try {
      await api.post("/findings/batch-delete", { ids: selected });
      setSelected([]);
      load();
    } catch (exc) {
      onError(exc.message);
    }
  };

  const header = (column, label) => (
    <th
      className="sortable"
      onClick={() =>
        setSort((current) => ({
          column,
          order: current.column === column && current.order === "desc" ? "asc" : "desc",
        }))
      }
    >
      {label}
      {sort.column === column ? (sort.order === "desc" ? " ↓" : " ↑") : ""}
    </th>
  );

  if (!project) return null;

  return (
    <div>
      <Banner kind="ok" onClose={() => setMessage("")}>
        {message}
      </Banner>

      <div className="card">
        <div className="row">
          <input
            style={{ width: 260 }}
            placeholder="search CVE, component, title"
            value={filters.q}
            onChange={(event) => setFilters({ ...filters, q: event.target.value })}
          />
          <select
            style={{ width: 130 }}
            value={filters.severity}
            onChange={(event) => setFilters({ ...filters, severity: event.target.value })}
          >
            <option value="">any severity</option>
            {meta.severities.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
          <select
            style={{ width: 140 }}
            value={filters.status}
            onChange={(event) => setFilters({ ...filters, status: event.target.value })}
          >
            <option value="">any status</option>
            {meta.statuses.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
          <select
            style={{ width: 130 }}
            value={filters.scan_type}
            onChange={(event) => setFilters({ ...filters, scan_type: event.target.value })}
          >
            <option value="">any type</option>
            {meta.scan_types.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
          <select
            style={{ width: 120 }}
            value={filters.tool}
            onChange={(event) => setFilters({ ...filters, tool: event.target.value })}
          >
            <option value="">any tool</option>
            {tools.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
          <select
            style={{ width: 130 }}
            value={filters.has_patch}
            onChange={(event) => setFilters({ ...filters, has_patch: event.target.value })}
          >
            <option value="">patch: any</option>
            <option value="true">has a patch</option>
            <option value="false">no patch</option>
          </select>
          <select
            style={{ width: 120 }}
            value={filters.has_plan}
            onChange={(event) => setFilters({ ...filters, has_plan: event.target.value })}
          >
            <option value="">plan: any</option>
            <option value="true">in a plan</option>
            <option value="false">no plan</option>
          </select>
          <select
            style={{ width: 130 }}
            value={filters.reported}
            onChange={(event) => setFilters({ ...filters, reported: event.target.value })}
          >
            <option value="">reported: any</option>
            <option value="true">reported</option>
            <option value="false">not reported</option>
          </select>
          <div className="grow" style={{ flex: 1 }} />
          {loading ? <Spinner /> : <span className="muted">{page ? page.total : 0} findings</span>}
        </div>
      </div>

      {selected.length > 0 && (
        <div className="card" style={{ borderColor: "var(--ember)" }}>
          <div className="row">
            <strong>{selected.length} selected</strong>
            <select
              style={{ width: 160 }}
              defaultValue=""
              onChange={(event) => event.target.value && bulk({ status: event.target.value })}
            >
              <option value="">set status…</option>
              {meta.statuses.map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select>
            <button onClick={() => setPlanModal(true)}>create a plan from these</button>
            <button onClick={() => bulk({ reported: true })}>mark reported</button>
            <button className="danger" onClick={removeSelected}>
              delete
            </button>
            <button className="ghost" onClick={() => setSelected([])}>
              clear
            </button>
          </div>
        </div>
      )}

      <div className="card scroll-x">
        {items.length === 0 ? (
          <Empty title="No findings match">
            Change the filters, or run a scan to fill this project.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th style={{ width: 28 }}>
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={() => setSelected(allSelected ? [] : items.map((item) => item.id))}
                  />
                </th>
                {header("ref", "Id")}
                {header("cve_id", "CVE")}
                {header("severity", "Severity")}
                <th className="right">Base</th>
                <th className="right">Adapted</th>
                <th>Components</th>
                {header("status", "Status")}
                {header("tool", "Tool")}
                <th>Plan</th>
                <th className="right">Age</th>
              </tr>
            </thead>
            <tbody>
              {items.map((finding) => (
                <tr
                  key={finding.id}
                  className={rowClass(finding, selected.includes(finding.id))}
                  onClick={() => setOpen(finding)}
                  style={{ cursor: "pointer" }}
                >
                  <td onClick={(event) => event.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selected.includes(finding.id)}
                      onChange={() => toggle(finding.id)}
                    />
                  </td>
                  <td className="ref">
                    {finding.ref}
                    {finding.regressed_at ? <span className="pill bad" style={{ marginLeft: 6 }}>regression</span> : null}
                  </td>
                  <td className="ref">{finding.cve_id || finding.external_id || "—"}</td>
                  <td className={`sev ${finding.severity}`}>{finding.severity}</td>
                  <td className="right mono">{formatScore(finding.cvss_base_score)}</td>
                  <td className="right mono">{formatScore(finding.adapted_score)}</td>
                  <td className="truncate">{finding.components.split("\n")[0]}</td>
                  <td>{finding.status}</td>
                  <td className="muted">{finding.tool || "manual"}</td>
                  <td className="muted truncate" style={{ maxWidth: 160 }}>
                    {finding.plan_name || "—"}
                  </td>
                  <td className="right">
                    <span className={finding.sla_overdue ? "sev Critical" : "muted"}>{finding.age_days}d</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {open && (
        <FindingDrawer
          finding={open}
          meta={meta}
          onClose={() => setOpen(null)}
          onSaved={() => {
            setOpen(null);
            load();
          }}
          onError={onError}
        />
      )}

      {planModal && (
        <PlanModal
          project={project}
          findingIds={selected}
          onClose={() => setPlanModal(false)}
          onCreated={(plan) => {
            setPlanModal(false);
            setSelected([]);
            navigate("plans", plan.id);
          }}
          onError={onError}
        />
      )}
    </div>
  );
}

function FindingDrawer({ finding, meta, onClose, onSaved, onError }) {
  const [draft, setDraft] = useState(finding);
  const [patch, setPatch] = useState(finding.patch || {});
  const [override, setOverride] = useState({});
  const [score, setScore] = useState(null);
  const [tab, setTab] = useState("triage");

  useEffect(() => {
    api.get(`/cvss/finding/${finding.id}/override`).then(setOverride).catch(() => {});
    if (finding.cvss_vector) {
      api.get(`/cvss/finding/${finding.id}`).then(setScore).catch(() => {});
    }
  }, [finding]);

  const save = async () => {
    try {
      await api.put(`/findings/${finding.id}`, {
        severity: draft.severity,
        status: draft.status,
        scan_type: draft.scan_type,
        components: draft.components,
        mitigation: draft.mitigation,
        title: draft.title,
        cvss_vector: draft.cvss_vector,
        cve_id: draft.cve_id,
        reported: draft.reported,
      });
      if (Object.keys(patch).length > 0) {
        await api.put(`/patches/finding/${finding.id}`, {
          fixed_version: patch.fixed_version || "",
          patch_pub_date: patch.patch_pub_date || null,
          functional_impact: patch.functional_impact || "",
          operational_impact: patch.operational_impact || "",
          regression_tests: patch.regression_tests || "",
          schedule: patch.schedule || "",
          applied_at: patch.applied_at || null,
          comments: patch.comments || "",
        });
      }
      onSaved();
    } catch (exc) {
      onError(exc.message);
    }
  };

  const saveOverride = async () => {
    try {
      const result = await api.put(`/cvss/finding/${finding.id}/override`, override);
      setScore(result);
    } catch (exc) {
      onError(exc.message);
    }
  };

  const refreshNvd = async () => {
    try {
      const result = await api.post(`/cvss/finding/${finding.id}/refresh?force=true`);
      setDraft({ ...draft, cvss_vector: result.vector });
    } catch (exc) {
      onError(exc.message);
    }
  };

  return (
    <Drawer title={`${finding.ref} · ${finding.cve_id || finding.external_id || "manual finding"}`} onClose={onClose}>
      <div className="tabs">
        {["triage", "fix", "scoring", "raw"].map((item) => (
          <button key={item} className={`tab ${tab === item ? "active" : ""}`} onClick={() => setTab(item)}>
            {item}
          </button>
        ))}
      </div>

      {tab === "triage" && (
        <div>
          <Field label="Title">
            <input value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} />
          </Field>
          <div className="grid cols-3">
            <Field label="Severity" hint={draft.cvss_vector ? "follows the adapted score" : "manual"}>
              <select
                value={draft.severity}
                disabled={Boolean(draft.cvss_vector)}
                onChange={(event) => setDraft({ ...draft, severity: event.target.value })}
              >
                {meta.severities.map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </Field>
            <Field label="Status">
              <select value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
                {meta.statuses.map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </Field>
            <Field label="Scan type">
              <select
                value={draft.scan_type}
                onChange={(event) => setDraft({ ...draft, scan_type: event.target.value })}
              >
                {meta.scan_types.map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="Affected components" hint="one component@version per line">
            <textarea
              value={draft.components}
              onChange={(event) => setDraft({ ...draft, components: event.target.value })}
            />
          </Field>
          <Field label="Mitigation" hint="required to close a Risk accepted finding">
            <textarea
              value={draft.mitigation}
              onChange={(event) => setDraft({ ...draft, mitigation: event.target.value })}
            />
          </Field>
          <div className="row muted" style={{ fontSize: 12 }}>
            <span>detected {formatDate(finding.created_at)}</span>
            <span>· {finding.age_days} days old, SLA {finding.sla_days} days</span>
            {finding.days_since_publication !== null && (
              <span>· published {finding.days_since_publication} days ago</span>
            )}
            <span>· origin {finding.origin}</span>
          </div>
        </div>
      )}

      {tab === "fix" && (
        <div>
          <div className="grid cols-2">
            <Field label="Fixed in version">
              <input
                value={patch.fixed_version || ""}
                onChange={(event) => setPatch({ ...patch, fixed_version: event.target.value })}
              />
            </Field>
            <Field label="Upstream published">
              <input
                type="date"
                value={patch.patch_pub_date || ""}
                onChange={(event) => setPatch({ ...patch, patch_pub_date: event.target.value })}
              />
            </Field>
          </div>
          <Field label="Functional impact">
            <textarea
              value={patch.functional_impact || ""}
              onChange={(event) => setPatch({ ...patch, functional_impact: event.target.value })}
            />
          </Field>
          <Field label="Operational impact">
            <textarea
              value={patch.operational_impact || ""}
              onChange={(event) => setPatch({ ...patch, operational_impact: event.target.value })}
            />
          </Field>
          <Field label="Regression tests">
            <textarea
              value={patch.regression_tests || ""}
              onChange={(event) => setPatch({ ...patch, regression_tests: event.target.value })}
            />
          </Field>
          <div className="grid cols-2">
            <Field label="Schedule" hint="a date or a release name">
              <input
                value={patch.schedule || ""}
                onChange={(event) => setPatch({ ...patch, schedule: event.target.value })}
              />
            </Field>
            <Field label="Applied on">
              <input
                type="date"
                value={patch.applied_at || ""}
                onChange={(event) => setPatch({ ...patch, applied_at: event.target.value })}
              />
            </Field>
          </div>
          {finding.plan_name ? (
            <p className="muted">Part of the plan {finding.plan_name}.</p>
          ) : (
            <p className="muted">Not in a plan yet. Select rows in the list to build one.</p>
          )}
        </div>
      )}

      {tab === "scoring" && (
        <div>
          <Field label="Base vector">
            <input
              className="mono"
              value={draft.cvss_vector}
              onChange={(event) => setDraft({ ...draft, cvss_vector: event.target.value })}
            />
          </Field>
          <div className="row" style={{ marginBottom: 12 }}>
            <button className="small" onClick={refreshNvd}>
              fetch from the NVD
            </button>
            {score && (
              <span className="muted">
                base <strong>{formatScore(score.base_score)}</strong> · temporal{" "}
                <strong>{formatScore(score.temporal_score)}</strong> · adapted{" "}
                <strong className={`sev ${score.adapted_severity}`}>{formatScore(score.adapted_score)}</strong>
              </span>
            )}
          </div>
          {score && <div className="log" style={{ marginBottom: 12 }}>{score.vector}</div>}
          <h3 style={{ marginBottom: 8 }}>Per finding overrides</h3>
          <p className="muted" style={{ marginTop: 0 }}>
            Empty means the project selection applies.
          </p>
          <div className="grid cols-2">
            {METRICS.map(([key, label, values]) => (
              <Field key={key} label={`${key} · ${label}`}>
                <select
                  value={override[key] || ""}
                  onChange={(event) => setOverride({ ...override, [key]: event.target.value || null })}
                >
                  <option value="">project default</option>
                  {values.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </Field>
            ))}
          </div>
          <button onClick={saveOverride}>save overrides and rescore</button>
        </div>
      )}

      {tab === "raw" && (
        <div>
          <Field label="CVE id">
            <input value={draft.cve_id || ""} onChange={(event) => setDraft({ ...draft, cve_id: event.target.value })} />
          </Field>
          <p className="muted">
            External id {finding.external_id || "—"} · tool {finding.tool || "manual"} · file{" "}
            {finding.file_path || "—"}
            {finding.line ? `:${finding.line}` : ""}
          </p>
          <div className="log">{finding.description || "no description"}</div>
        </div>
      )}

      <div className="row" style={{ marginTop: 18 }}>
        <button className="primary" onClick={save}>
          save
        </button>
        <button className="ghost" onClick={onClose}>
          cancel
        </button>
      </div>
    </Drawer>
  );
}

function PlanModal({ project, findingIds, onClose, onCreated, onError }) {
  const [draft, setDraft] = useState({ name: "", target_version: "", target_date: "", owner: "" });

  const submit = async () => {
    try {
      const plan = await api.post("/plans", {
        project_id: project.id,
        name: draft.name,
        target_version: draft.target_version,
        target_date: draft.target_date || null,
        owner: draft.owner,
        finding_ids: findingIds,
      });
      onCreated(plan);
    } catch (exc) {
      onError(exc.message);
    }
  };

  return (
    <Modal title={`New plan from ${findingIds.length} findings`} onClose={onClose}>
      <Field label="Name">
        <input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} />
      </Field>
      <div className="grid cols-2">
        <Field label="Target version">
          <input
            value={draft.target_version}
            onChange={(event) => setDraft({ ...draft, target_version: event.target.value })}
          />
        </Field>
        <Field label="Target date">
          <input
            type="date"
            value={draft.target_date}
            onChange={(event) => setDraft({ ...draft, target_date: event.target.value })}
          />
        </Field>
      </div>
      <Field label="Owner">
        <input value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} />
      </Field>
      <button className="primary" disabled={!draft.name} onClick={submit}>
        create plan
      </button>
    </Modal>
  );
}
