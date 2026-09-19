import type { Vals } from "../model";

export function WhyItExists({ v }: { v: Vals }) {
  return (
    <div id="por-que" className="wrap sec">
      <div className="split">
        <div style={{ display: "flex", flexDirection: "column", gap: "20px", maxWidth: "60ch" }}>
          <span style={{ fontSize: "15px", fontWeight: "600", color: "#0B6B69" }}>{v.t.wEyebrow}</span>
          <h2
            className="disp h2"
            style={{ margin: "0", lineHeight: "1.08", letterSpacing: "-0.03em", fontWeight: "700", textWrap: "balance" }}
          >
            {v.t.wTitle}
          </h2>
          <p style={{ margin: "0", fontSize: "18px", lineHeight: "1.6", color: "#4F5C5B", textWrap: "pretty" }}>{v.t.wBody1}</p>
          <p style={{ margin: "0", fontSize: "18px", lineHeight: "1.6", color: "#4F5C5B", textWrap: "pretty" }}>{v.t.wBody2}</p>
        </div>
        <div
          style={{
            padding: "32px",
            borderRadius: "28px",
            background: "#FFFFFF",
            boxShadow: "0 1px 2px rgba(19,32,31,0.04), 0 30px 60px -44px rgba(19,52,50,0.30)",
            display: "flex",
            flexDirection: "column",
            gap: "22px",
          }}
        >
          <span style={{ fontSize: "14px", color: "#5E6B6A" }}>{v.t.pAward}</span>
          <div style={{ display: "flex", height: "56px", gap: "6px" }}>
            <div
              style={{
                flex: "70",
                display: "flex",
                alignItems: "center",
                padding: "0 18px",
                borderRadius: "16px",
                background: "#E6EBEA",
                fontSize: "14.5px",
                color: "#4F5C5B",
                minWidth: "0",
              }}
            >
              {v.t.pRest}
            </div>
            <div
              style={{
                flex: "30",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                padding: "0 12px",
                borderRadius: "16px",
                background: "#0B6B69",
                fontSize: "14.5px",
                fontWeight: "600",
                color: "#FFFFFF",
                whiteSpace: "nowrap",
              }}
            >
              {v.t.pTranche}
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", fontSize: "14px", color: "#5E6B6A" }}>
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#0B6B69"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <rect x="5" y="11" width="14" height="10" rx="2"></rect>
              <path d="M8 11V8a4 4 0 0 1 8 0v3"></path>
            </svg>
            {v.t.pUnlock}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "14px",
                padding: "14px 16px",
                borderRadius: "16px",
                background: "#F2F4F3",
              }}
            >
              <svg
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#13201F"
                strokeWidth="1.7"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M6 3h8l5 5v13H6z"></path>
                <path d="M14 3v5h5"></path>
              </svg>
              <span style={{ fontSize: "16px", fontWeight: "500" }}>{v.t.pDoc1}</span>
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "14px",
                padding: "14px 16px",
                borderRadius: "16px",
                background: "#F2F4F3",
              }}
            >
              <svg
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#13201F"
                strokeWidth="1.7"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M6 3h8l5 5v13H6z"></path>
                <path d="M14 3v5h5"></path>
              </svg>
              <span style={{ fontSize: "16px", fontWeight: "500" }}>{v.t.pDoc2}</span>
            </div>
          </div>
          <span style={{ fontSize: "14px", lineHeight: "1.5", color: "#5E6B6A" }}>{v.t.pFoot}</span>
        </div>
      </div>
    </div>
  );
}
