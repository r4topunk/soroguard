import type { Vals } from "../model";

export function HowItWorks({ v }: { v: Vals }) {
  return (
    <div id="como" className="wrap sec">
      <div style={{ display: "flex", flexDirection: "column", gap: "16px", maxWidth: "65ch" }}>
        <span style={{ fontSize: "15px", fontWeight: "600", color: "#0B6B69" }}>{v.t.hEyebrow}</span>
        <h2
          className="disp h2"
          style={{ margin: "0", lineHeight: "1.08", letterSpacing: "-0.03em", fontWeight: "700", textWrap: "balance" }}
        >
          {v.t.hTitle}
        </h2>
        <p style={{ margin: "0", fontSize: "18px", lineHeight: "1.6", color: "#4F5C5B", textWrap: "pretty" }}>{v.t.hSub}</p>
      </div>
      <div className="g4" style={{ marginTop: "36px" }}>
        {v.steps.map((st, i0) => (
          <div
            key={i0}
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "14px",
              padding: "24px",
              borderRadius: "28px",
              background: "#FFFFFF",
              boxShadow: "0 1px 2px rgba(19,32,31,0.04), 0 30px 60px -44px rgba(19,52,50,0.30)",
              minWidth: "0",
            }}
          >
            <span
              style={{
                display: "grid",
                placeItems: "center",
                width: "32px",
                height: "32px",
                borderRadius: "50%",
                background: "#F2F4F3",
                fontSize: "14px",
                fontWeight: "600",
                color: "#4F5C5B",
              }}
            >
              {st.n}
            </span>
            <span
              className="disp"
              style={{ fontSize: "20px", lineHeight: "1.25", fontWeight: "700", letterSpacing: "-0.015em", color: "#13201F" }}
            >
              {st.title}
            </span>
            <span style={{ fontSize: "15.5px", lineHeight: "1.55", color: "#4F5C5B" }}>{st.body}</span>
            <span
              className="mono"
              style={{
                marginTop: "auto",
                padding: "10px 12px",
                borderRadius: "14px",
                background: "#F2F4F3",
                fontSize: "13px",
                color: "#0A5E5C",
                overflowWrap: "anywhere",
              }}
            >
              {st.code}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
