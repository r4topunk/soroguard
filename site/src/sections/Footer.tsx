import type { Vals } from "../model";

export function Footer({ v }: { v: Vals }) {
  return (
    <div className="wrap" style={{ paddingTop: "120px", paddingBottom: "56px" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "16px 32px",
          flexWrap: "wrap",
          paddingTop: "28px",
          boxShadow: "inset 0 1px 0 #E0E6E4",
          fontSize: "14.5px",
          color: "#5E6B6A",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px 20px", flexWrap: "wrap" }}>
          <span className="disp" style={{ fontSize: "17px", fontWeight: "700", color: "#13201F" }}>
            soroguard
          </span>
          <span>Apache-2.0</span>
          <span>Node ≥ 22.18</span>
          <span>{v.t.fBuilt}</span>
        </div>
        <a
          className="textlink"
          href="https://github.com/r4topunk/soroguard"
          style={{ display: "inline-flex", alignItems: "center", minHeight: "44px", fontWeight: "500", color: "#0B6B69" }}
        >
          github.com/r4topunk/soroguard
        </a>
      </div>
    </div>
  );
}
