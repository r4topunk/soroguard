import type { Vals } from "../model";
import { sx } from "../sx";

export function TopBar({ v }: { v: Vals }) {
  return (
    <div
      style={{
        position: "sticky",
        top: "0",
        zIndex: "20",
        background: "rgba(242,244,243,0.84)",
        backdropFilter: "blur(14px)",
        WebkitBackdropFilter: "blur(14px)",
        boxShadow: "0 1px 0 rgba(19,32,31,0.05)",
      }}
    >
      <div className="wrap" style={{ height: "72px", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "16px" }}>
        <a href="#top" style={{ display: "flex", alignItems: "center", gap: "10px", minHeight: "44px" }}>
          <span
            style={{ display: "grid", placeItems: "center", width: "34px", height: "34px", borderRadius: "11px", background: "#0B6B69" }}
          >
            <svg
              width="19"
              height="19"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#FFFFFF"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 3l7 3v5.5c0 4.6-3 8.1-7 9.5-4-1.4-7-4.9-7-9.5V6z"></path>
              <path d="M9 12l2 2 4-4"></path>
            </svg>
          </span>
          <span className="disp" style={{ fontWeight: "700", fontSize: "21px", letterSpacing: "-0.02em" }}>
            soroguard
          </span>
        </a>
        <nav className="navlinks" aria-label={v.t.navAria}>
          <a className="navlink" href="#como">
            {v.t.nav0}
          </a>
          <a className="navlink" href="#explorar">
            {v.t.nav1}
          </a>
          <a className="navlink" href="#evidencia">
            {v.t.nav2}
          </a>
          <a className="navlink" href="#resultado">
            {v.t.nav3}
          </a>
          <a className="navlink" href="#por-que">
            {v.t.nav5}
          </a>
          <a className="navlink" href="#comecar">
            {v.t.nav4}
          </a>
        </nav>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <div
            style={{ display: "flex", padding: "3px", borderRadius: "999px", background: "#E3E8E7" }}
            role="group"
            aria-label="Idioma / Language"
          >
            {v.langs.map((l, i0) => (
              <button key={i0} onClick={l.pick} aria-pressed={l.pressed} style={sx(l.style)}>
                {l.label}
              </button>
            ))}
          </div>
          <a
            className="ghost"
            href="https://github.com/r4topunk/soroguard"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              minHeight: "44px",
              padding: "0 14px",
              borderRadius: "999px",
              fontSize: "15px",
              fontWeight: "500",
              color: "#13201F",
              transition: "background .2s ease",
            }}
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21"></path>
            </svg>
            GitHub
          </a>
        </div>
      </div>
    </div>
  );
}
