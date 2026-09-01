import React, { useCallback, useEffect, useState } from "react";

import { api, formatDate, formatScore } from "../api.js";
import { Banner, Empty, Field, Modal, Spinner } from "../components.jsx";

export default function Plans({ project, meta, argument, navigate, onError }) {
  const [plans, setPlans] = useState(null);
  const [openId, setOpenId] = useState(argument ? Number(argument) : null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    if (!project) return;
    try {
      setPlans(await api.get("/plans", { project_id: project.id }));
    } catch (exc) {
      onError(exc.message);
    }
  }, [project, onError]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (argument) setOpenId(Number(argument));
  }, [argument]);

  if (!project) return null;
  if (!plans) return <Spinner label="loading" />;

  if (openId) {
    return (
      <PlanDetail
        planId={openId}
        meta={meta}
        onBack={() => {
          setOpenId(null);
          navigate("plans");
          load();
        }}
        onError={onError}
      />
    );
  }

  return (
    <div>
      <div className="card">
        <div className="card-head">
          <h2 className="grow">Remediation waves in {project.key}</h2>
          <button className="primary small" onClick={() => setCreating(true)}>
            new plan
          </button>
        </div>
        {plans.length === 0 ? (
          <Empty title="No plan yet">
            Filter the findings list, select the rows that ship together and create a plan in one action.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Id</th>
                <th>Name</th>
                <th>Target version</th>
                <th>Target date</th>
                <th>Owner</th>
                <th>Status</th>
                <th className="right">Fixed</th>
                <th>Missing</th>
              </tr>
            </thead>
            <tbody>
              {plans.map((plan) => (
                <tr key={plan.id} onClick={() => setOpenId(plan.id)} style={{ cursor: "pointer" }}>
                  <td className="ref">{plan.ref}</td>
                  <td>{plan.name}</td>
                  <td className="mono">{plan.target_version || "—"}</td>
                  <td className={plan.overdue ? "sev Critical nowrap" : "nowrap"}>{formatDate(plan.target_date)}</td>
                  <td className="muted">{plan.owner || "—"}</td>
                  <td>
                    <span className={`pill ${plan.status === "Done" ? "ok" : plan.overdue ? "bad" : ""}`}>
                      {plan.status}
                    </span>
                  </td>
                  <td className="right">
                    {plan.fixed_count}/{plan.finding_count}
                  </td>
                  <td className="muted">{plan.missing.length ? `${plan.missing.length} gaps` : "complete"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {creating && (
        <NewPlan
          project={project}
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            load();
          }}
          onError={onError}
        />
      )}
    </div>
  );
}

function PlanDetail({ planId, meta, onBack, onError }) {
  const [plan, setPlan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setPlan(await api.get(`/plans/${planId}`));
      setFindings(await api.get(`/plans/${planId}/findings`));
    } catch (exc) {
      onError(exc.message);
    }
  }, [planId, onError]);

  useEffect(() => {
    load();
  }, [load]);

  if (!plan) return <Spinner label="loading" />;

  const setStatus = async (status) => {
    if (status === "Done" && plan.missing.length > 0) {
      const message =
        `${plan.missing.length} items are still incomplete:\n\n${plan.missing.slice(0, 8).join("\n")}` +
        "\n\nClose the plan anyway? Findings marked Risk accepted stay as they are.";
      if (!window.confirm(message)) return;
    }
    try {
      await api.put(`/plans/${planId}`, { status });
      setNotice(status === "Done" ? "plan closed, its findings are now Fixed" : `plan is now ${status}`);
      load();
    } catch (exc) {
      onError(exc.message);
    }
  };

  const detach = async (findingId) => {
    await api.del(`/plans/${planId}/findings/${findingId}`);
    load();
  };

  return (
    <div>
      <div className="row" style={{ marginBottom: 12 }}>
        <button className="ghost small" onClick={onBack}>
          ← all plans
        </button>
      </div>
      <Banner kind="ok" onClose={() => setNotice("")}>
        {notice}
      </Banner>

      <div className="card">
        <div className="card-head">
          <h2 className="grow">
            <span className="ref">{plan.ref}</span> {plan.name}
          </h2>
          <select style={{ width: 160 }} value={plan.status} onChange={(event) => setStatus(event.target.value)}>
            {meta.plan_statuses.map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        </div>
        <div className="grid cols-4">
          <div className="stat">
            <div className="value">{plan.finding_count}</div>
            <div className="label">findings in the wave</div>
          </div>
          <div className="stat">
            <div className="value" style={{ color: "var(--ok)" }}>{plan.fixed_count}</div>
            <div className="label">already fixed</div>
          </div>
          <div className="stat">
            <div className="value">{plan.target_version || "—"}</div>
            <div className="label">target version</div>
          </div>
          <div className="stat">
            <div className="value" style={{ color: plan.overdue ? "var(--critical)" : undefined }}>
              {formatDate(plan.target_date)}
            </div>
            <div className="label">target date{plan.overdue ? " (overdue)" : ""}</div>
          </div>
        </div>
        {plan.notes ? <p className="muted">{plan.notes}</p> : null}
      </div>

      {plan.missing.length > 0 && (
        <div className="card">
          <h2>What is still missing</h2>
          <ul className="muted" style={{ margin: "8px 0 0", paddingLeft: 18 }}>
            {plan.missing.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="card scroll-x">
        <h2>Findings and their fix</h2>
        <table>
          <thead>
            <tr>
              <th>Id</th>
              <th>Severity</th>
              <th className="right">Score</th>
              <th>Component</th>
              <th>Status</th>
              <th>Fixed in</th>
              <th>Regression tests</th>
              <th>Schedule</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.id} className={finding.status === "Fixed" ? "resolved" : ""}>
                <td className="ref">{finding.ref}</td>
                <td className={`sev ${finding.severity}`}>{finding.severity}</td>
                <td className="right mono">{formatScore(finding.adapted_score)}</td>
                <td className="truncate">{finding.components.split("\n")[0]}</td>
                <td>{finding.status}</td>
                <td className="mono">{finding.patch ? finding.patch.fixed_version || "—" : "—"}</td>
                <td className="muted truncate" style={{ maxWidth: 220 }}>
                  {finding.patch ? finding.patch.regression_tests || "—" : "—"}
                </td>
                <td className="muted">{finding.patch ? finding.patch.schedule || "—" : "—"}</td>
                <td>
                  <button className="ghost small" onClick={() => detach(finding.id)}>
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function NewPlan({ project, onClose, onCreated, onError }) {
  const [draft, setDraft] = useState({ name: "", target_version: "", target_date: "", owner: "", notes: "" });

  const submit = async () => {
    try {
      await api.post("/plans", {
        project_id: project.id,
        ...draft,
        target_date: draft.target_date || null,
      });
      onCreated();
    } catch (exc) {
      onError(exc.message);
    }
  };

  return (
    <Modal title="New plan" onClose={onClose}>
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
      <Field label="Notes">
        <textarea value={draft.notes} onChange={(event) => setDraft({ ...draft, notes: event.target.value })} />
      </Field>
      <button className="primary" disabled={!draft.name} onClick={submit}>
        create
      </button>
    </Modal>
  );
}
