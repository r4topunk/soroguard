import type { Vals } from "../model";
import { sx } from "../sx";

export function Explore({ v }: { v: Vals }) {
  return (
    <div id="explorar" className="wrap sec">
      <div style={{ display: "flex", flexDirection: "column", gap: "16px", maxWidth: "65ch" }}>
        <span style={{ fontSize: "15px", fontWeight: "600", color: "#0B6B69" }}>{v.t.xEyebrow}</span>
        <h2
          className="disp h2"
          style={{ margin: "0", lineHeight: "1.08", letterSpacing: "-0.03em", fontWeight: "700", textWrap: "balance" }}
        >
          {v.t.xTitle}
        </h2>
        <p style={{ margin: "0", fontSize: "18px", lineHeight: "1.6", color: "#4F5C5B", textWrap: "pretty" }}>{v.t.xSub}</p>
      </div>

      <div
        style={{
          marginTop: "36px",
          padding: "24px",
          borderRadius: "28px",
          background: "#FFFFFF",
          boxShadow: "0 1px 2px rgba(19,32,31,0.04), 0 30px 60px -44px rgba(19,52,50,0.30)",
        }}
      >
        <div className="explorer">
          <div
            style={{ display: "flex", flexDirection: "column", gap: "4px", padding: "8px", borderRadius: "22px", background: "#F2F4F3" }}
            role="group"
            aria-label={v.t.xFnsAria}
          >
            <span className="mono" style={{ padding: "8px 12px 10px", fontSize: "13px", color: "#5E6B6A" }}>
              escrow · CDZZ5HUO…742T5
            </span>
            {v.fns.map((it, i0) => (
              <button key={i0} onClick={it.pick} aria-pressed={it.pressed} style={sx(it.style)}>
                <span className="mono" style={{ fontSize: "14.5px" }}>
                  {it.name}
                </span>
                <span style={sx(it.dot)}></span>
              </button>
            ))}
            <div style={{ display: "flex", flexWrap: "wrap", gap: "14px", padding: "12px 12px 6px", fontSize: "13px", color: "#5E6B6A" }}>
              <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#0B6B69" }}></span>
                {v.t.xLegOk}
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#C4552B" }}></span>
                {v.t.xLegBad}
              </span>
              <span style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#B9C3C1" }}></span>
                {v.t.xLegNone}
              </span>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "16px", paddingTop: "6px", minWidth: "0" }}>
            <span style={{ fontSize: "15px", color: "#5E6B6A" }}>
              <span className="mono" style={{ color: "#13201F", fontWeight: "500" }}>
                {v.cur.name}
              </span>{" "}
              {v.cur.verb}
            </span>
            <div className="g2">
              {v.chips.map((c, i0) => (
                <div key={i0} style={sx(c.style)}>
                  <span style={sx(c.iconWrap)}>
                    <svg
                      width="20"
                      height="20"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.9"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d={c.icon}></path>
                    </svg>
                  </span>
                  <span style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: "0", flex: "1" }}>
                    <span className="mono" style={{ fontSize: "14px", fontWeight: "500" }}>
                      {c.fn}
                    </span>
                    <span style={{ fontSize: "14px" }}>{c.sub}</span>
                  </span>
                  <span style={sx(c.stateStyle)}>{c.state}</span>
                </div>
              ))}
            </div>
            <div style={sx(v.cur.panel)} aria-live="polite">
              <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
                <span style={sx(v.cur.tokenStyle)}>{v.cur.token}</span>
                <span className="disp" style={{ fontSize: "20px", fontWeight: "700", letterSpacing: "-0.015em", color: "#13201F" }}>
                  {v.cur.title}
                </span>
              </div>
              {v.cur.lines.map((ln, i0) => (
                <div
                  key={i0}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "12px",
                    fontSize: "15.5px",
                    lineHeight: "1.5",
                    color: "#33403F",
                  }}
                >
                  <span style={sx(ln.tokenStyle)}>{ln.tier}</span>
                  <span style={{ paddingTop: "3px" }}>{ln.text}</span>
                </div>
              ))}
              <span style={{ fontSize: "15px", lineHeight: "1.55", color: "#4F5C5B" }}>{v.cur.note}</span>
            </div>
          </div>
        </div>
      </div>
      <p style={{ margin: "20px 4px 0", maxWidth: "65ch", fontSize: "15px", lineHeight: "1.6", color: "#5E6B6A" }}>{v.t.xRule}</p>
    </div>
  );
}
