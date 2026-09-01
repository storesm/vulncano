import React, { useEffect, useState } from "react";

import { api, formatDate } from "../api.js";
import { Empty, SeverityBar, Spinner } from "../components.jsx";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

export default function Dashboard({ project, navigate, onError }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    if (!project) return;
    setData(null);
    api
      .get("/findings/dashboard", { project_id: project.id })
      .then(setData)
      .catch((exc) => onError(exc.message));
  }, [project, onError]);

  if (!project) return null;
  if (!data) return <Spinner label="loading" />;

  const open = (data.by_status.New || 0) + (data.by_status.Confirmed || 0);

  return (
    <div>
      <div className="grid cols-4">
        <div className="stat">
          <div className="value">{data.total}</div>
          <div className="label">findings in {project.key}</div>
        </div>
        <div className="stat">
          <div className="value" style={{ color: "var(--ember)" }}>{open}</div>
          <div className="label">still open (New or Confirmed)</div>
        </div>
        <div className="stat">
          <div className="value">{data.without_plan}</div>
          <div className="label">open with no fix plan</div>
        </div>
        <div className="stat">
          <div className="value" style={{ color: data.sla_breaches.length ? "var(--critical)" : undefined }}>
            {data.sla_breaches.length}
          </div>
          <div className="label">past their SLA window</div>
        </div>
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-head">
          <h2 className="grow">Severity</h2>
          <button className="small" onClick={() => navigate("findings")}>
            open findings
          </button>
        </div>
        <SeverityBar counts={data.by_severity} />
        <div className="row" style={{ marginTop: 10 }}>
          {SEVERITIES.map((severity) => (
            <span key={severity} className="row tight" style={{ marginRight: 14 }}>
              <span className={`sev ${severity}`}>{severity}</span>
              <strong>{data.by_severity[severity] || 0}</strong>
            </span>
          ))}
        </div>
      </div>

      <div className="grid cols-2" style={{ marginTop: 14 }}>
        <div className="card">
          <h2>Past the SLA window</h2>
          {data.sla_breaches.length === 0 ? (
            <Empty title="Nothing overdue">Every open finding is inside the window configured for its severity.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Id</th>
                  <th>Severity</th>
                  <th>Age</th>
                  <th>Allowed</th>
                  <th>Component</th>
                </tr>
              </thead>
              <tbody>
                {data.sla_breaches.slice(0, 10).map((finding) => (
                  <tr key={finding.id} onClick={() => navigate("findings", finding.ref)} style={{ cursor: "pointer" }}>
                    <td className="ref">{finding.ref}</td>
                    <td className={`sev ${finding.severity}`}>{finding.severity}</td>
                    <td>{finding.age_days}d</td>
                    <td className="muted">{finding.sla_days}d</td>
                    <td className="truncate">{finding.components.split("\n")[0]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <h2>Plans past their target date</h2>
          {data.overdue_plans.length === 0 ? (
            <Empty title="No overdue plan">Plans are either inside their target date, done or cancelled.</Empty>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Id</th>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Fixed</th>
                </tr>
              </thead>
              <tbody>
                {data.overdue_plans.map((plan) => (
                  <tr key={plan.id} onClick={() => navigate("plans", plan.id)} style={{ cursor: "pointer" }}>
                    <td className="ref">{plan.ref}</td>
                    <td>{plan.name}</td>
                    <td className="nowrap">{formatDate(plan.target_date)}</td>
                    <td>
                      {plan.fixed_count}/{plan.finding_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h2 className="grow">Recent scans</h2>
          <button className="small primary" onClick={() => navigate("scan")}>
            new scan
          </button>
        </div>
        {data.recent_scans.length === 0 ? (
          <Empty title="No scan yet">
            Upload a manifest or a scanner report on the Scan screen. OSV.dev needs no credentials.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Id</th>
                <th>Tool</th>
                <th>Source</th>
                <th>Status</th>
                <th className="right">Parsed</th>
                <th className="right">Imported</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="ref">{scan.ref}</td>
                  <td>{scan.tool}</td>
                  <td className="truncate">{scan.source}</td>
                  <td>
                    <span className={`pill ${scan.status === "failed" ? "bad" : scan.status === "imported" ? "ok" : ""}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="right">{scan.parsed_count}</td>
                  <td className="right">{scan.imported_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
