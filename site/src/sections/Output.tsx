import type { Vals } from "../model";
import { sx } from "../sx";

export function Output({ v }: { v: Vals }) {
  return (
    <div id="resultado" className="wrap sec">
      <div style={{ display: "flex", flexDirection: "column", gap: "16px", maxWidth: "65ch" }}>
        <span style={{ fontSize: "15px", fontWeight: "600", color: "#0B6B69" }}>{v.t.oEyebrow}</span>
        <h2
          className="disp h2"
          style={{ margin: "0", lineHeight: "1.08", letterSpacing: "-0.03em", fontWeight: "700", textWrap: "balance" }}
        >
          {v.t.oTitle}
        </h2>
        <p style={{ margin: "0", fontSize: "18px", lineHeight: "1.6", color: "#4F5C5B", textWrap: "pretty" }}>{v.t.oSub}</p>
      </div>

      <div
        style={{
          marginTop: "36px",
          padding: "24px",
          borderRadius: "28px",
          background: "#FFFFFF",
          boxShadow: "0 1px 2px rgba(19,32,31,0.04), 0 30px 60px -44px rgba(19,52,50,0.30)",
          display: "flex",
          flexDirection: "column",
          gap: "20px",
        }}
      >
        <div className="outboard">
          <div style={{ padding: "8px", borderRadius: "22px", background: "#F2F4F3", minWidth: "0" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: "2px 12px",
                minHeight: "56px",
                padding: "8px 12px",
                boxSizing: "border-box",
              }}
            >
              <span style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: "0" }}>
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#13201F"
                  strokeWidth="1.7"
                  strokeLinejoin="round"
                  aria-hidden="true"
                  style={{ flex: "none" }}
                >
                  <path d="M6 3h8l5 5v13H6z"></path>
                  <path d="M14 3v5h5"></path>
                </svg>
                <span className="mono" style={{ fontSize: "14px", fontWeight: "500", color: "#13201F", whiteSpace: "nowrap" }}>
                  threat-model.md
                </span>
              </span>
              <span style={{ flex: "none", fontSize: "13px", color: "#5E6B6A" }}>{v.t.oTmCount}</span>
            </div>
            <div role="group" aria-label={v.t.oTmAria} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              {v.tmRows.map((r, i0) => (
                <button key={i0} className="outrow" onClick={r.pick} aria-pressed={r.pressed} style={sx(r.style)}>
                  <span style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: "0", flex: "1" }}>
                    <span
                      className="mono"
                      style={{ fontSize: "14px", fontWeight: "500", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}
                    >
                      {r.id}
                    </span>
                    <span
                      style={{ fontSize: "13.5px", color: "#5E6B6A", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}
                    >
                      {r.sub}
                    </span>
                  </span>
                  <span style={{ display: "flex", gap: "6px", flex: "none" }}>
                    {r.toks.map((tk, i1) => (
                      <span key={i1} style={sx(tk.style)}>
                        {tk.label}
                      </span>
                    ))}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div className="outlink" aria-hidden="true">
            <svg width="120" height="256" viewBox="0 0 120 256" style={{ display: "block", overflow: "visible" }}>
              <defs>
                <marker id="out-arr" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                  <path d="M0 0.5 L9 5 L0 9.5 z" fill="#0B6B69"></path>
                </marker>
              </defs>
              {v.wires.map((w, i0) => (
                <path
                  key={v.outKey + "-" + i0}
                  d={w.d}
                  pathLength={w.len}
                  className={w.cls}
                  fill="none"
                  stroke={w.color}
                  strokeWidth={w.width}
                  strokeDasharray={w.dash}
                  strokeLinecap="round"
                  markerEnd={w.marker}
                ></path>
              ))}
              {v.marks.map((m, i0) => (
                <g key={v.outKey + "-" + i0} className="sg-fade">
                  <circle cx={m.cx} cy={m.cy} r="10" fill={m.fill} stroke={m.stroke} strokeWidth="1.4"></circle>
                  <path d={m.glyph} fill="none" stroke={m.stroke} strokeWidth="1.7" strokeLinecap="round"></path>
                </g>
              ))}
              {v.labels.map((lb, i0) => (
                <text key={v.outKey + "-" + i0} x="60" y={lb.y} textAnchor="middle" fontSize="12.5" fill={lb.color} className="sg-fade">
                  {lb.text}
                </text>
              ))}
            </svg>
          </div>

          <div style={{ padding: "8px", borderRadius: "22px", background: "#F2F4F3", minWidth: "0" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: "2px 12px",
                minHeight: "56px",
                padding: "8px 12px",
                boxSizing: "border-box",
              }}
            >
              <span style={{ display: "flex", alignItems: "center", gap: "10px", minWidth: "0" }}>
                <svg
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#13201F"
                  strokeWidth="1.7"
                  strokeLinejoin="round"
                  aria-hidden="true"
                  style={{ flex: "none" }}
                >
                  <path d="M6 3h8l5 5v13H6z"></path>
                  <path d="M14 3v5h5"></path>
                </svg>
                <span className="mono" style={{ fontSize: "14px", fontWeight: "500", color: "#13201F", whiteSpace: "nowrap" }}>
                  monitoring-plan.md
                </span>
              </span>
              <span style={{ flex: "none", fontSize: "13px", color: "#5E6B6A" }}>{v.t.oMpCount}</span>
            </div>
            <div role="group" aria-label={v.t.oMpAria} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              {v.mpRows.map((r, i0) => (
                <button key={i0} className="outrow" onClick={r.pick} aria-pressed={r.pressed} style={sx(r.style)}>
                  <span style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: "0", flex: "1" }}>
                    <span
                      className="mono"
                      style={{ fontSize: "14px", fontWeight: "500", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}
                    >
                      {r.id}
                    </span>
                    <span
                      style={{ fontSize: "13.5px", color: "#5E6B6A", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}
                    >
                      {r.sub}
                    </span>
                  </span>
                  <span style={{ display: "flex", gap: "6px", flex: "none" }}>
                    {r.toks.map((tk, i1) => (
                      <span key={i1} style={sx(tk.style)}>
                        {tk.label}
                      </span>
                    ))}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div style={sx(v.od.panel)} aria-live="polite">
          <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
            <span style={sx(v.od.tokenStyle)}>{v.od.token}</span>
            <span className="disp" style={{ fontSize: "20px", fontWeight: "700", letterSpacing: "-0.015em", color: "#13201F" }}>
              {v.od.title}
            </span>
          </div>
          <div className="g2" style={{ gap: "20px" }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              <span style={{ fontSize: "13.5px", fontWeight: "600", color: "#4F5C5B" }}>{v.t.oWhat}</span>
              <span style={{ fontSize: "15.5px", lineHeight: "1.55", color: "#33403F" }}>{v.od.what}</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              <span style={{ fontSize: "13.5px", fontWeight: "600", color: "#4F5C5B" }}>{v.t.oWatch}</span>
              <span style={{ fontSize: "15.5px", lineHeight: "1.55", color: "#33403F" }}>{v.od.watch}</span>
            </div>
          </div>
          {v.od.lines.map((ln, i0) => (
            <div
              key={i0}
              style={{ display: "flex", alignItems: "flex-start", gap: "12px", fontSize: "15px", lineHeight: "1.5", color: "#33403F" }}
            >
              <span style={sx(ln.tokenStyle)}>{ln.tier}</span>
              <span style={{ paddingTop: "3px" }}>{ln.text}</span>
            </div>
          ))}
          {v.od.todo.map((td, i0) => (
            <div
              key={i0}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "10px",
                paddingTop: "12px",
                boxShadow: "inset 0 1px 0 rgba(19,32,31,0.07)",
                fontSize: "15px",
                lineHeight: "1.5",
                color: "#33403F",
              }}
            >
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#855300"
                strokeWidth="1.9"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
                style={{ flex: "none", marginTop: "2px" }}
              >
                <path d="M4 20h4L19 9l-4-4L4 16z"></path>
                <path d="M13.5 6.5l4 4"></path>
              </svg>
              <span>
                <span style={{ fontWeight: "600" }}>{v.t.oTodo}</span> {td.text}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ marginTop: "20px", display: "flex", flexWrap: "wrap", gap: "8px" }}>
        {v.verdicts.map((vd, i0) => (
          <span
            key={i0}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "10px",
              minHeight: "36px",
              padding: "6px 14px",
              boxSizing: "border-box",
              borderRadius: "999px",
              background: "#FFFFFF",
              fontSize: "14px",
              color: "#4F5C5B",
              boxShadow: "0 1px 2px rgba(19,32,31,0.05)",
            }}
          >
            <span style={{ flex: "none", width: "8px", height: "8px", borderRadius: "50%", background: "#A66F0A" }}></span>
            {vd.text}
          </span>
        ))}
      </div>
      <div style={{ marginTop: "24px", display: "flex", flexDirection: "column", gap: "14px", maxWidth: "65ch" }}>
        <p style={{ margin: "0", fontSize: "17px", lineHeight: "1.6", color: "#13201F", fontWeight: "500", textWrap: "pretty" }}>
          {v.t.oRule}
        </p>
        <p style={{ margin: "0", fontSize: "16.5px", lineHeight: "1.65", color: "#4F5C5B", textWrap: "pretty" }}>{v.t.oNumbers}</p>
      </div>
    </div>
  );
}
