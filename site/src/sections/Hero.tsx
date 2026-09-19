import type { Vals } from "../model";
import { sx } from "../sx";

export function Hero({ v }: { v: Vals }) {
  return (
    <div
      id="top"
      className="wrap"
      style={{ paddingTop: "88px", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center" }}
    >
      <span
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "8px",
          padding: "7px 14px 7px 10px",
          borderRadius: "999px",
          background: "#FFFFFF",
          fontSize: "14px",
          color: "#4F5C5B",
          boxShadow: "0 1px 2px rgba(19,32,31,0.05)",
        }}
      >
        <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#0B6B69", boxShadow: "0 0 0 4px #DDEFEC" }}></span>
        {v.t.eyebrow}
      </span>
      <h1
        className="disp h1"
        style={{
          margin: "28px 0 0",
          lineHeight: "1.02",
          letterSpacing: "-0.035em",
          fontWeight: "700",
          color: "#13201F",
          maxWidth: "980px",
          textWrap: "balance",
        }}
      >
        <span style={{ display: "block" }}>{v.t.h1a}</span>
        <span style={{ display: "block", color: "#5E6B6A", fontWeight: "600" }}>{v.t.h1b}</span>
      </h1>
      <p style={{ margin: "24px 0 0", maxWidth: "62ch", fontSize: "20px", lineHeight: "1.55", color: "#4F5C5B", textWrap: "pretty" }}>
        {v.t.heroSub}
      </p>

      <button className="capsule" onClick={v.pickCopy} aria-label={v.copyAria} style={sx(v.capsule)}>
        <span
          style={{
            display: "grid",
            placeItems: "center",
            flex: "none",
            width: "48px",
            height: "48px",
            borderRadius: "16px",
            background: "#DDEFEC",
            color: "#0B6B69",
          }}
        >
          <svg
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M5 7l5 5-5 5"></path>
            <path d="M13 17h6"></path>
          </svg>
        </span>
        <span className="mono keycmd" style={{ letterSpacing: "-0.01em", color: "#13201F", textAlign: "left" }}>
          npx soroguard artifact <span style={{ color: "#0B6B69" }}>&lt;contract-id&gt;</span>
        </span>
        <span style={sx(v.copyKey)}>
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d={v.copyIcon}></path>
          </svg>
          {v.copyLabel}
        </span>
      </button>
      <a
        className="textlink"
        href="#explorar"
        style={{
          marginTop: "18px",
          display: "inline-flex",
          alignItems: "center",
          gap: "8px",
          minHeight: "44px",
          padding: "0 12px",
          fontSize: "16px",
          fontWeight: "500",
          color: "#0B6B69",
        }}
      >
        {v.t.heroLink}
        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M12 5v14"></path>
          <path d="M6 13l6 6 6-6"></path>
        </svg>
      </a>

      {/* hero diagram */}
      <div
        style={{
          marginTop: "56px",
          width: "100%",
          padding: "32px 32px 24px",
          boxSizing: "border-box",
          borderRadius: "28px",
          background: "#FFFFFF",
          boxShadow: "0 1px 2px rgba(19,32,31,0.04), 0 30px 60px -44px rgba(19,52,50,0.30)",
          textAlign: "left",
        }}
      >
        <div className="dgscroll">
          <svg
            width="1200"
            height="452"
            viewBox="0 0 1200 452"
            role="img"
            aria-label={v.t.dgAria}
            style={{ display: "block", width: "100%", minWidth: "880px", height: "auto" }}
          >
            <defs>
              <marker id="lg-arr" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                <path d="M0 0.5 L9 5 L0 9.5 z" fill="#9AA6A4"></path>
              </marker>
              <marker id="lg-arr-a" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                <path d="M0 0.5 L9 5 L0 9.5 z" fill="#0B6B69"></path>
              </marker>
              <marker id="lg-arr-b" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                <path d="M0 0.5 L9 5 L0 9.5 z" fill="#A66F0A"></path>
              </marker>
              <marker id="lg-arr-c" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto">
                <path d="M0 0.5 L9 5 L0 9.5 z" fill="#4760B5"></path>
              </marker>
            </defs>

            {/* step headers */}
            <circle cx="12" cy="18" r="12" fill="#F2F4F3"></circle>
            <text x="12" y="22.5" textAnchor="middle" fontSize="12.5" fontWeight="600" fill="#4F5C5B">
              1
            </text>
            <text x="34" y="23.5" fontSize="15.5" fontWeight="600" fill="#13201F">
              {v.t.dgS1}
            </text>
            <circle cx="260" cy="18" r="12" fill="#F2F4F3"></circle>
            <text x="260" y="22.5" textAnchor="middle" fontSize="12.5" fontWeight="600" fill="#4F5C5B">
              2
            </text>
            <text x="282" y="23.5" fontSize="15.5" fontWeight="600" fill="#13201F">
              {v.t.dgS2}
            </text>
            <circle cx="504" cy="18" r="12" fill="#F2F4F3"></circle>
            <text x="504" y="22.5" textAnchor="middle" fontSize="12.5" fontWeight="600" fill="#4F5C5B">
              3
            </text>
            <text x="526" y="23.5" fontSize="15.5" fontWeight="600" fill="#13201F">
              {v.t.dgS3}
            </text>
            <circle cx="992" cy="18" r="12" fill="#F2F4F3"></circle>
            <text x="992" y="22.5" textAnchor="middle" fontSize="12.5" fontWeight="600" fill="#4F5C5B">
              4
            </text>
            <text x="1014" y="23.5" fontSize="15.5" fontWeight="600" fill="#13201F">
              {v.t.dgS4}
            </text>

            {/* 1 · contract id */}
            <rect x="0.5" y="160.5" width="196" height="104" rx="18" fill="#F2F4F3"></rect>
            <text x="20" y="192" fontSize="13" fill="#5E6B6A">
              Contract ID
            </text>
            <text x="20" y="220" className="mono" fontSize="15.5" fontWeight="500" fill="#13201F">
              CDZZ5HUO…742T5
            </text>
            <text x="20" y="246" fontSize="13" fill="#5E6B6A">
              escrow · mainnet
            </text>
            <path d="M198 212 H242" stroke="#9AA6A4" strokeWidth="1.5" fill="none" markerEnd="url(#lg-arr)"></path>

            {/* 2 · wasm */}
            <rect x="248.5" y="92.5" width="196" height="240" rx="18" fill="#F2F4F3"></rect>
            <text x="268" y="130" className="disp" fontSize="22" fontWeight="700" fill="#13201F">
              WASM
            </text>
            <text x="268" y="152" fontSize="13" fill="#5E6B6A">
              {v.t.dgWasmSub}
            </text>
            <g className="mono" fontSize="12.5" fill="#5E6B6A">
              <text x="268" y="190">
                00 61 73 6d 01 00 00
              </text>
              <rect x="260" y="199" width="176" height="24" rx="8" fill="#DDEFEC"></rect>
              <text x="268" y="215" fill="#0A5E5C">
                02 3c 06 01 61 01 30
              </text>
              <text x="268" y="240">
                01 6c 01 5f 00 01 78
              </text>
              <text x="268" y="265">
                04 00 0a 8f 02 1a 20
              </text>
            </g>
            <path d="M268 286.5 H426" stroke="#E0E6E4"></path>
            <text x="268" y="312" className="mono" fontSize="12.5" fill="#0A5E5C">
              a.0 = require_auth
            </text>
            <path d="M446 212 H490" stroke="#9AA6A4" strokeWidth="1.5" fill="none" markerEnd="url(#lg-arr)"></path>

            {/* network node */}
            <path d="M98 266 V354" stroke="#C9D1CF" strokeWidth="1.5" fill="none"></path>
            <rect x="0.5" y="356.5" width="444" height="64" rx="18" fill="#F2F4F3"></rect>
            <g transform="translate(20 374)" fill="none" stroke="#A66F0A" strokeWidth="1.8" strokeLinecap="round">
              <circle cx="14" cy="14" r="3" fill="#A66F0A" stroke="none"></circle>
              <path d="M7.6 7.6a9 9 0 0 0 0 12.8M20.4 7.6a9 9 0 0 1 0 12.8"></path>
              <path d="M3.4 3.4a15 15 0 0 0 0 21.2M24.6 3.4a15 15 0 0 1 0 21.2"></path>
            </g>
            <text x="62" y="384" fontSize="15" fontWeight="600" fill="#13201F">
              {v.t.dgNet}
            </text>
            <text x="62" y="405" fontSize="13" fill="#5E6B6A">
              {v.t.dgNetSub}
            </text>

            {/* 3 · buttons panel */}
            <rect x="496" y="52" width="440" height="344" rx="22" fill="#F2F4F3"></rect>
            <text x="516" y="86" fontSize="13" fill="#5E6B6A">
              {v.t.dgFns}
            </text>
            <text x="766" y="86" fontSize="13" fill="#5E6B6A">
              {v.t.dgHosts}
            </text>

            {/* reachable edges: possible paths (neutral, not evidence) */}
            <g fill="none" stroke="#A9B4B2" strokeWidth="1.5" strokeLinecap="round">
              <path d="M696 160 C731 160 731 196 766 196"></path>
              <path d="M696 160 C731 160 731 266 766 266"></path>
              <path d="M696 160 C731 160 731 336 766 336"></path>
              <path d="M696 246 C731 246 731 126 766 126"></path>
              <path d="M696 246 C731 246 731 266 766 266"></path>
              <path d="M696 246 C731 246 731 336 766 336"></path>
            </g>
            {/* proven absence: initialize_escrow never reaches require_auth */}
            <circle cx="731" cy="136" r="10" fill="#FBEAE2" stroke="#C4552B" strokeWidth="1.4"></circle>
            <path d="M727 132l8 8M735 132l-8 8" stroke="#C4552B" strokeWidth="1.7" strokeLinecap="round"></path>

            {/* function pills */}
            <g className="mono" fontSize="14">
              <rect x="516" y="138" width="180" height="44" rx="14" fill="#FFFFFF"></rect>
              <text x="532" y="165" fill="#13201F">
                initialize_escrow
              </text>
              <rect x="516" y="224" width="180" height="44" rx="14" fill="#FFFFFF"></rect>
              <text x="532" y="251" fill="#13201F">
                fund_escrow
              </text>
              <rect x="516" y="310" width="180" height="44" rx="14" fill="#FFFFFF"></rect>
              <text x="532" y="337" fill="#13201F">
                get_escrow
              </text>
            </g>
            <text x="532" y="378" fontSize="12.5" fill="#5E6B6A">
              {v.t.dgNone}
            </text>

            {/* host buttons */}
            <g className="mono" fontSize="12.5">
              <rect x="766" y="106" width="158" height="40" rx="20" fill="#FFFFFF"></rect>
              <circle cx="784" cy="126" r="4.5" fill="#13201F"></circle>
              <text x="797" y="130.5" fill="#13201F">
                require_auth
              </text>
              <rect x="766" y="176" width="158" height="40" rx="20" fill="#FFFFFF"></rect>
              <circle cx="784" cy="196" r="4.5" fill="#13201F"></circle>
              <text x="797" y="200.5" fill="#13201F">
                put_contract_data
              </text>
              <rect x="766" y="246" width="158" height="40" rx="20" fill="#FFFFFF"></rect>
              <circle cx="784" cy="266" r="4.5" fill="#13201F"></circle>
              <text x="797" y="270.5" fill="#13201F">
                contract_event
              </text>
              <rect x="766" y="316" width="158" height="40" rx="20" fill="#FFFFFF"></rect>
              <circle cx="784" cy="336" r="4.5" fill="#13201F"></circle>
              <text x="797" y="340.5" fill="#13201F">
                call
              </text>
            </g>

            {/* tier A: bytecode fact (solid) */}
            <path d="M936 150 C962 150 966 104 994 104" fill="none" stroke="#0B6B69" strokeWidth="2.2" markerEnd="url(#lg-arr-a)"></path>
            <circle cx="962" cy="126" r="11" fill="#DDEFEC" stroke="#0B6B69" strokeWidth="1.4"></circle>
            <text x="962" y="130.5" textAnchor="middle" fontSize="12" fontWeight="700" fill="#0A5E5C">
              A
            </text>
            {/* tier C: inference (dotted) */}
            <path
              d="M936 206 C962 206 966 176 994 176"
              fill="none"
              stroke="#4760B5"
              strokeWidth="2.6"
              strokeDasharray="0.1 5.5"
              strokeLinecap="round"
              markerEnd="url(#lg-arr-c)"
            ></path>
            <circle cx="962" cy="192" r="11" fill="#E4E9F6" stroke="#4760B5" strokeWidth="1.4"></circle>
            <text x="962" y="196.5" textAnchor="middle" fontSize="12" fontWeight="700" fill="#34509E">
              C
            </text>
            {/* tier B: observed on-chain (dashed) */}
            <path
              d="M445 388 C472 388 472 436 500 436 H940 C972 436 962 362 994 362"
              fill="none"
              stroke="#A66F0A"
              strokeWidth="2.2"
              strokeDasharray="7 5"
              markerEnd="url(#lg-arr-b)"
            ></path>
            <circle cx="716" cy="436" r="11" fill="#F6ECD4" stroke="#A66F0A" strokeWidth="1.4"></circle>
            <text x="716" y="440.5" textAnchor="middle" fontSize="12" fontWeight="700" fill="#855300">
              B
            </text>

            {/* doc 1 */}
            <rect x="996" y="52" width="204" height="180" rx="18" fill="#F2F4F3"></rect>
            <g transform="translate(1014 70)" fill="none" stroke="#13201F" strokeWidth="1.6" strokeLinejoin="round">
              <path d="M1 1h10l6 6v15H1z"></path>
              <path d="M11 1v6h6"></path>
            </g>
            <text x="1040" y="86" className="disp" fontSize="16.5" fontWeight="700" fill="#13201F">
              {v.t.dgDoc1}
            </text>
            <text x="1014" y="114" className="mono" fontSize="12" fill="#5E6B6A">
              threat-model.md
            </text>
            <path d="M1014 128.5 H1182" stroke="#E0E6E4"></path>
            <text x="1014" y="154" className="mono" fontSize="12.5" fill="#13201F">
              Elevation.1 · Medium
            </text>
            <text x="1014" y="182" fontSize="13" fill="#33403F">
              {v.t.dgRow1b}
            </text>
            <rect x="1160" y="168" width="22" height="20" rx="6" fill="#DDEFEC"></rect>
            <text x="1171" y="182.5" textAnchor="middle" fontSize="12" fontWeight="700" fill="#0A5E5C">
              A
            </text>
            <text x="1014" y="210" fontSize="13" fill="#33403F">
              {v.t.dgRow1c}
            </text>
            <rect x="1160" y="196" width="22" height="20" rx="6" fill="#E4E9F6"></rect>
            <text x="1171" y="210.5" textAnchor="middle" fontSize="12" fontWeight="700" fill="#34509E">
              C
            </text>

            {/* same id link */}
            <path d="M1098 233 V282" stroke="#C9D1CF" strokeWidth="1.5"></path>
            <text x="1110" y="262" fontSize="12.5" fill="#5E6B6A">
              {v.t.dgSameId}
            </text>

            {/* doc 2 */}
            <rect x="996" y="284" width="204" height="152" rx="18" fill="#F2F4F3"></rect>
            <g transform="translate(1014 302)" fill="none" stroke="#13201F" strokeWidth="1.6" strokeLinejoin="round">
              <path d="M1 1h10l6 6v15H1z"></path>
              <path d="M11 1v6h6"></path>
            </g>
            <text x="1040" y="318" className="disp" fontSize="16.5" fontWeight="700" fill="#13201F">
              {v.t.dgDoc2}
            </text>
            <text x="1014" y="346" className="mono" fontSize="12" fill="#5E6B6A">
              monitoring-plan.md
            </text>
            <path d="M1014 360.5 H1182" stroke="#E0E6E4"></path>
            <text x="1014" y="386" className="mono" fontSize="12.5" fill="#13201F">
              Elevation.1.M.1
            </text>
            <text x="1014" y="414" fontSize="13" fill="#33403F">
              {v.t.dgRow2b}
            </text>
            <rect x="1160" y="400" width="22" height="20" rx="6" fill="#F6ECD4"></rect>
            <text x="1171" y="414.5" textAnchor="middle" fontSize="12" fontWeight="700" fill="#855300">
              B
            </text>
          </svg>
        </div>

        {/* legend */}
        <div style={{ marginTop: "20px", display: "flex", flexWrap: "wrap", gap: "10px 28px", fontSize: "14px", color: "#4F5C5B" }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "10px" }}>
            <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
              <path d="M2 5 H34" stroke="#0B6B69" strokeWidth="2.4" strokeLinecap="round"></path>
            </svg>
            {v.t.lgA}
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "10px" }}>
            <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
              <path d="M2 5 H34" stroke="#A66F0A" strokeWidth="2.4" strokeDasharray="7 5"></path>
            </svg>
            {v.t.lgB}
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "10px" }}>
            <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
              <path d="M3 5 H34" stroke="#4760B5" strokeWidth="2.8" strokeDasharray="0.1 5.5" strokeLinecap="round"></path>
            </svg>
            {v.t.lgC}
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "10px" }}>
            <svg width="36" height="10" viewBox="0 0 36 10" aria-hidden="true">
              <path d="M2 5 H34" stroke="#A9B4B2" strokeWidth="1.6" strokeLinecap="round"></path>
            </svg>
            {v.t.lgP}
          </span>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "10px" }}>
            <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true">
              <circle cx="10" cy="10" r="8.5" fill="#FBEAE2" stroke="#C4552B" strokeWidth="1.3"></circle>
              <path d="M6.8 6.8l6.4 6.4M13.2 6.8l-6.4 6.4" stroke="#C4552B" strokeWidth="1.6" strokeLinecap="round"></path>
            </svg>
            {v.t.lgX}
          </span>
        </div>
      </div>
    </div>
  );
}
