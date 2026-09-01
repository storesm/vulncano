import React from "react";

export function Banner({ kind = "info", children, onClose }) {
  if (!children) return null;
  return (
    <div className={`banner ${kind}`}>
      <div className="row">
        <div className="grow" style={{ flex: 1 }}>{children}</div>
        {onClose && (
          <button className="ghost small" onClick={onClose}>
            dismiss
          </button>
        )}
      </div>
    </div>
  );
}

export function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span>
        {label}
        {hint ? <em className="muted"> — {hint}</em> : null}
      </span>
      {children}
    </label>
  );
}

export function Modal({ title, children, onClose, wide }) {
  return (
    <div className="overlay center" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="modal" style={wide ? { width: "min(900px, calc(100% - 32px))" } : undefined}>
        <div className="card-head">
          <h2 className="grow">{title}</h2>
          <button className="ghost small" onClick={onClose}>
            close
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Drawer({ title, children, onClose }) {
  return (
    <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="drawer">
        <div className="card-head">
          <h2 className="grow">{title}</h2>
          <button className="ghost small" onClick={onClose}>
            close
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Empty({ title, children }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      <div>{children}</div>
    </div>
  );
}

export function Spinner({ label }) {
  return (
    <span className="row tight">
      <span className="spinner" />
      {label ? <span className="muted">{label}</span> : null}
    </span>
  );
}

export function SeverityBar({ counts }) {
  const order = ["Critical", "High", "Medium", "Low", "Info"];
  const total = order.reduce((sum, key) => sum + (counts[key] || 0), 0) || 1;
  return (
    <div className="bar">
      {order.map((severity) => (
        <span
          key={severity}
          title={`${severity}: ${counts[severity] || 0}`}
          style={{
            width: `${((counts[severity] || 0) / total) * 100}%`,
            background: `var(--${severity.toLowerCase()})`,
          }}
        />
      ))}
    </div>
  );
}
