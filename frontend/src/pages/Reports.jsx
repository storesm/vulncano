import React, { useCallback, useEffect, useState } from "react";

import { api, formatDate } from "../api.js";
import { Banner, Empty, Field, Spinner } from "../components.jsx";

const POLL_MS = 900;

export default function Reports({ project, onError }) {
  const [templates, setTemplates] = useState([]);
  const [plans, setPlans] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({
    scope: "project",
    plan_id: "",
    template: "default",
    output_format: "pdf",
    title: "Vulnerability report",
    document_code: "",
    version: "1.0",
    authors: "",
    software_version: "",
    analysis_date: new Date().toISOString().slice(0, 10),
    include_unreported_only: false,
  });

  const loadJobs = useCallback(async () => {
    try {
      setJobs(await api.get("/reports"));
    } catch (exc) {
      onError(exc.message);
    }
  }, [onError]);

  useEffect(() => {
    api.get("/reports/templates").then(setTemplates).catch(() => {});
    loadJobs();
  }, [loadJobs]);

  useEffect(() => {
    if (!project) return;
    api.get("/plans", { project_id: project.id }).then(setPlans).catch(() => {});
  }, [project]);

  const generate = async () => {
    setBusy(true);
    try {
      const job = await api.post("/reports/generate", {
        project_id: form.scope === "project" ? project.id : null,
        plan_id: form.scope === "plan" && form.plan_id ? Number(form.plan_id) : null,
        template: form.template,
        output_format: form.output_format,
        title: form.title,
        document_code: form.document_code,
        version: form.version,
        authors: form.authors,
        software_version: form.software_version,
        analysis_date: form.analysis_date || null,
        include_unreported_only: form.include_unreported_only,
      });
      await waitFor(job.id);
    } catch (exc) {
      onError(exc.message);
    } finally {
      setBusy(false);
      loadJobs();
    }
  };

  const waitFor = async (jobId) => {
    for (let attempt = 0; attempt < 80; attempt += 1) {
      const job = await api.get(`/reports/${jobId}`);
      if (job.status === "done") {
        setNotice(`report ${jobId} is ready`);
        return;
      }
      if (job.status === "failed") {
        onError(job.error);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }
    onError("the report job did not finish in time, check the server log");
  };

  const markReported = async (jobId) => {
    const result = await api.post(`/reports/${jobId}/mark-reported`);
    setNotice(`${result.marked} findings marked as reported`);
  };

  if (!project) return null;

  return (
    <div>
      <Banner kind="ok" onClose={() => setNotice("")}>
        {notice}
      </Banner>

      <div className="grid cols-2">
        <div className="card">
          <h2>Scope</h2>
          <Field label="What goes in">
            <select value={form.scope} onChange={(event) => setForm({ ...form, scope: event.target.value })}>
              <option value="project">the whole project ({project.key})</option>
              <option value="plan">one remediation plan</option>
            </select>
          </Field>
          {form.scope === "plan" && (
            <Field label="Plan">
              <select value={form.plan_id} onChange={(event) => setForm({ ...form, plan_id: event.target.value })}>
                <option value="">pick a plan</option>
                {plans.map((plan) => (
                  <option key={plan.id} value={plan.id}>
                    {plan.ref} — {plan.name}
                  </option>
                ))}
              </select>
            </Field>
          )}
          <label className="row tight" style={{ marginBottom: 12 }}>
            <input
              type="checkbox"
              checked={form.include_unreported_only}
              onChange={(event) => setForm({ ...form, include_unreported_only: event.target.checked })}
            />
            <span>only what has not been reported yet</span>
          </label>
          <div className="grid cols-2">
            <Field label="Template">
              <select value={form.template} onChange={(event) => setForm({ ...form, template: event.target.value })}>
                {templates.map((item) => (
                  <option key={item.name} value={item.name}>
                    {item.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Format">
              <select
                value={form.output_format}
                onChange={(event) => setForm({ ...form, output_format: event.target.value })}
              >
                <option value="pdf">PDF</option>
                <option value="html">HTML</option>
                <option value="md">Markdown</option>
              </select>
            </Field>
          </div>
          <p className="muted" style={{ fontSize: 12 }}>
            A report is refused when something is missing rather than printing an empty cell. The
            offending finding ids come back in the error.
          </p>
        </div>

        <div className="card">
          <h2>Document metadata</h2>
          <Field label="Title">
            <input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} />
          </Field>
          <div className="grid cols-2">
            <Field label="Document code">
              <input
                value={form.document_code}
                onChange={(event) => setForm({ ...form, document_code: event.target.value })}
              />
            </Field>
            <Field label="Version">
              <input value={form.version} onChange={(event) => setForm({ ...form, version: event.target.value })} />
            </Field>
          </div>
          <div className="grid cols-2">
            <Field label="Authors">
              <input value={form.authors} onChange={(event) => setForm({ ...form, authors: event.target.value })} />
            </Field>
            <Field label="Software version">
              <input
                value={form.software_version}
                onChange={(event) => setForm({ ...form, software_version: event.target.value })}
              />
            </Field>
          </div>
          <Field label="Analysis date">
            <input
              type="date"
              value={form.analysis_date}
              onChange={(event) => setForm({ ...form, analysis_date: event.target.value })}
            />
          </Field>
          <button className="primary" disabled={busy} onClick={generate}>
            {busy ? <Spinner label="rendering" /> : "generate"}
          </button>
        </div>
      </div>

      <div className="card">
        <h2>Generated documents</h2>
        {jobs.length === 0 ? (
          <Empty title="Nothing generated yet">Reports appear here with their template bundle.</Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Job</th>
                <th>Template</th>
                <th>Format</th>
                <th>Status</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id}>
                  <td className="ref">#{job.id}</td>
                  <td>{job.template}</td>
                  <td className="mono">{job.output_format}</td>
                  <td>
                    <span className={`pill ${job.status === "done" ? "ok" : job.status === "failed" ? "bad" : ""}`}>
                      {job.status}
                    </span>
                    {job.error ? <div className="muted" style={{ fontSize: 12 }}>{job.error}</div> : null}
                  </td>
                  <td className="nowrap muted">{formatDate(job.created_at)}</td>
                  <td>
                    <div className="row tight">
                      {job.download_url && (
                        <button className="small" onClick={() => api.download(job.download_url.replace("/api", ""))}>
                          download
                        </button>
                      )}
                      {job.bundle_url && (
                        <button className="small ghost" onClick={() => api.download(job.bundle_url.replace("/api", ""))}>
                          templates
                        </button>
                      )}
                      {job.status === "done" && (
                        <button className="small ghost" onClick={() => markReported(job.id)}>
                          mark reported
                        </button>
                      )}
                    </div>
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
