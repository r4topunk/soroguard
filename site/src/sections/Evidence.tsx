import type { Vals } from "../model";
import { sx } from "../sx";

export function Evidence({ v }: { v: Vals }) {
  return (
    <div id="evidencia" className="wrap sec">
      <div style={{ display: "flex", flexDirection: "column", gap: "16px", maxWidth: "65ch" }}>
        <span style={{ fontSize: "15px", fontWeight: "600", color: "#0B6B69" }}>{v.t.eEyebrow}</span>
        <h2
          className="disp h2"
          style={{ margin: "0", lineHeight: "1.08", letterSpacing: "-0.03em", fontWeight: "700", textWrap: "balance" }}
        >
          {v.t.eTitle}
        </h2>
        <p style={{ margin: "0", fontSize: "18px", lineHeight: "1.6", color: "#4F5C5B", textWrap: "pretty" }}>{v.t.eSub}</p>
      </div>
      <div className="split-ev" style={{ marginTop: "36px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }} role="group" aria-label={v.t.eTiersAria}>
          {v.tiers.map((tr, i0) => (
            <button key={i0} onClick={tr.pick} aria-pressed={tr.pressed} style={sx(tr.style)}>
              <span style={sx(tr.badge)}>{tr.k}</span>
              <span style={{ display: "flex", flexDirection: "column", gap: "3px", flex: "1", minWidth: "0" }}>
                <span style={{ fontSize: "17px", fontWeight: "600", color: "#13201F" }}>{tr.name}</span>
                <span style={{ fontSize: "14.5px", lineHeight: "1.45", color: "#5E6B6A" }}>{tr.desc}</span>
              </span>
              <svg width="56" height="12" viewBox="0 0 56 12" aria-hidden="true" style={{ flex: "none" }}>
                <path
                  d="M3 6 H53"
                  fill="none"
                  stroke={tr.color}
                  strokeWidth={tr.width}
                  strokeDasharray={tr.dash}
                  strokeLinecap="round"
                ></path>
              </svg>
            </button>
          ))}
        </div>
        <div
          style={{
            padding: "36px",
            borderRadius: "28px",
            background: "#FFFFFF",
            boxShadow: "0 1px 2px rgba(19,32,31,0.04), 0 30px 60px -44px rgba(19,52,50,0.30)",
            display: "flex",
            flexDirection: "column",
            gap: "20px",
          }}
          aria-live="polite"
        >
          <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
            <span style={sx(v.ev.badge)}>{v.ev.k}</span>
            <svg width="120" height="12" viewBox="0 0 120 12" aria-hidden="true">
              <path
                d="M3 6 H117"
                fill="none"
                stroke={v.ev.color}
                strokeWidth={v.ev.width}
                strokeDasharray={v.ev.dash}
                strokeLinecap="round"
              ></path>
            </svg>
            <span style={{ fontSize: "14px", color: "#5E6B6A" }}>{v.t.eExample}</span>
          </div>
          <p
            className="disp"
            style={{
              margin: "0",
              fontSize: "26px",
              lineHeight: "1.3",
              letterSpacing: "-0.015em",
              fontWeight: "600",
              color: "#13201F",
              textWrap: "pretty",
            }}
          >
            {v.ev.claim}
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", paddingTop: "18px", boxShadow: "inset 0 1px 0 #E6EBEA" }}>
            <span style={{ fontSize: "14px", fontWeight: "600", color: "#4F5C5B" }}>{v.t.eWhy}</span>
            <p style={{ margin: "0", fontSize: "16.5px", lineHeight: "1.6", color: "#33403F", maxWidth: "60ch" }}>{v.ev.why}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
