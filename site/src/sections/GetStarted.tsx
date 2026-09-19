import type { Vals } from "../model";
import { sx } from "../sx";

export function GetStarted({ v }: { v: Vals }) {
  return (
    <div id="comecar" className="wrap sec">
      <div style={{ display: "flex", flexDirection: "column", gap: "16px", maxWidth: "65ch" }}>
        <span style={{ fontSize: "15px", fontWeight: "600", color: "#0B6B69" }}>{v.t.sEyebrow}</span>
        <h2
          className="disp h2"
          style={{ margin: "0", lineHeight: "1.08", letterSpacing: "-0.03em", fontWeight: "700", textWrap: "balance" }}
        >
          {v.t.sTitle}
        </h2>
      </div>
      <div
        style={{ marginTop: "32px", display: "inline-flex", flexWrap: "wrap", padding: "4px", borderRadius: "22px", background: "#E3E8E7" }}
        role="group"
        aria-label={v.t.sTabsAria}
      >
        {v.tabs.map((tb, i0) => (
          <button key={i0} onClick={tb.pick} aria-pressed={tb.pressed} style={sx(tb.style)}>
            {tb.label}
          </button>
        ))}
      </div>
      <div
        style={{
          marginTop: "20px",
          padding: "28px 32px",
          borderRadius: "28px",
          background: "#FFFFFF",
          boxShadow: "0 1px 2px rgba(19,32,31,0.04), 0 30px 60px -44px rgba(19,52,50,0.30)",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
          overflowX: "auto",
        }}
      >
        {v.tab.lines.map((cl, i0) => (
          <div key={i0} className="mono" style={{ display: "flex", gap: "14px", fontSize: "15.5px", lineHeight: "1.6", whiteSpace: "pre" }}>
            <span style={sx(cl.preStyle)}>{cl.pre}</span>
            <span style={sx(cl.textStyle)}>{cl.text}</span>
          </div>
        ))}
      </div>
      <p style={{ margin: "18px 4px 0", maxWidth: "65ch", fontSize: "15.5px", lineHeight: "1.6", color: "#5E6B6A" }}>{v.tab.note}</p>
    </div>
  );
}
