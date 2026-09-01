import React, { useCallback, useEffect, useState } from "react";

import { api } from "./api.js";
import { Banner } from "./components.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Findings from "./pages/Findings.jsx";
import Plans from "./pages/Plans.jsx";
import Reports from "./pages/Reports.jsx";
import Scan from "./pages/Scan.jsx";
import Settings from "./pages/Settings.jsx";

const PAGES = [
  { id: "dashboard", label: "Dashboard", component: Dashboard },
  { id: "findings", label: "Findings", component: Findings },
  { id: "scan", label: "Scan", component: Scan },
  { id: "plans", label: "Plans", component: Plans },
  { id: "reports", label: "Reports", component: Reports },
  { id: "settings", label: "Settings", component: Settings },
];

function currentRoute() {
  const [page, argument] = window.location.hash.replace("#/", "").split("/");
  return { page: PAGES.some((item) => item.id === page) ? page : "dashboard", argument };
}

export default function App() {
  const [route, setRoute] = useState(currentRoute);
  const [projects, setProjects] = useState([]);
  const [projectId, setProjectId] = useState(() => Number(localStorage.getItem("vulncano.project")) || null);
  const [meta, setMeta] = useState({ severities: [], statuses: [], scan_types: [], plan_statuses: [] });
  const [error, setError] = useState("");

  const reloadProjects = useCallback(async () => {
    try {
      const list = await api.get("/projects");
      setProjects(list);
      setProjectId((current) => {
        if (current && list.some((item) => item.id === current)) return current;
        return list.length ? list[0].id : null;
      });
    } catch (exc) {
      setError(exc.message);
    }
  }, []);

  useEffect(() => {
    const onHashChange = () => setRoute(currentRoute());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    reloadProjects();
    api.get("/meta").then(setMeta).catch((exc) => setError(exc.message));
  }, [reloadProjects]);

  useEffect(() => {
    if (projectId) localStorage.setItem("vulncano.project", String(projectId));
  }, [projectId]);

  const navigate = (page, argument) => {
    window.location.hash = argument ? `#/${page}/${argument}` : `#/${page}`;
  };

  const active = PAGES.find((item) => item.id === route.page) || PAGES[0];
  const Page = active.component;
  const project = projects.find((item) => item.id === projectId) || null;

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">
          <img src="/logo.svg" alt="" />
          <span>
            Vuln<span className="ember">Cano</span>
          </span>
        </div>
        {PAGES.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${item.id === active.id ? "active" : ""}`}
            onClick={() => navigate(item.id)}
          >
            <span>{item.label}</span>
            {item.id === "findings" && project ? <span className="count">{project.finding_count}</span> : null}
          </button>
        ))}
        <div className="spacer" />
        <div className="foot">
          <a href="/docs" target="_blank" rel="noreferrer">
            API docs
          </a>
          <br />
          <a href="https://github.com/storesm/vulncano" target="_blank" rel="noreferrer">
            github.com/storesm/vulncano
          </a>
        </div>
      </nav>

      <div className="main">
        <header className="topbar">
          <h1>{active.label}</h1>
          <div className="grow" />
          {projects.length > 0 && (
            <select
              style={{ width: 240 }}
              value={projectId || ""}
              onChange={(event) => setProjectId(Number(event.target.value))}
            >
              {projects.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.key} — {item.name}
                </option>
              ))}
            </select>
          )}
        </header>

        <div className="content">
          <Banner kind="error" onClose={() => setError("")}>
            {error}
          </Banner>
          {projects.length === 0 && active.id !== "settings" ? (
            <div className="card">
              <h2>Start with a project</h2>
              <p className="muted">
                A project is the only grouping level in Vulncano. Create one in Settings, then scan
                a manifest or import a scanner report.
              </p>
              <button className="primary" onClick={() => navigate("settings")}>
                Go to settings
              </button>
            </div>
          ) : (
            <Page
              project={project}
              projects={projects}
              meta={meta}
              argument={route.argument}
              navigate={navigate}
              reloadProjects={reloadProjects}
              onError={setError}
            />
          )}
        </div>
      </div>
    </div>
  );
}
