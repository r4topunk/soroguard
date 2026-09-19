import { useCallback, useEffect, useRef, useState } from "react";
import { computeVals, type State } from "./model";
import type { Lang } from "./strings";
import { TopBar } from "./sections/TopBar";
import { Hero } from "./sections/Hero";
import { HowItWorks } from "./sections/HowItWorks";
import { Explore } from "./sections/Explore";
import { Evidence } from "./sections/Evidence";
import { Output } from "./sections/Output";
import { WhyItExists } from "./sections/WhyItExists";
import { GetStarted } from "./sections/GetStarted";
import { Footer } from "./sections/Footer";

const COMMAND = "npx soroguard artifact <contract-id>";
const TITLE: Record<Lang, string> = {
  pt: "soroguard · Modelo de ameaças para contratos Soroban",
  en: "soroguard · Threat models for Soroban contracts",
};

function initialLang(): Lang {
  return new URLSearchParams(window.location.search).get("lang") === "en" ? "en" : "pt";
}

export function App() {
  const [state, setFull] = useState<State>(() => ({
    lang: initialLang(),
    fn: "initialize_escrow",
    tier: "A",
    out: "el1",
    tab: "cli",
    copied: false,
  }));
  const setState = useCallback((patch: Partial<State>) => setFull((s) => ({ ...s, ...patch })), []);

  const copyTimer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(copyTimer.current), []);
  const pickCopy = useCallback(() => {
    try {
      navigator.clipboard?.writeText(COMMAND).catch(() => {});
    } catch {
      /* clipboard unavailable */
    }
    setState({ copied: true });
    window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setState({ copied: false }), 1800);
  }, [setState]);

  useEffect(() => {
    document.documentElement.lang = state.lang === "en" ? "en" : "pt-BR";
    document.title = TITLE[state.lang];
  }, [state.lang]);

  const v = computeVals(state, setState, { pickCopy });

  return (
    <div
      style={{
        width: "100%",
        boxSizing: "border-box",
        background: "#F2F4F3",
        backgroundImage: "radial-gradient(1100px 560px at 50% -140px, rgba(11,107,105,0.08), rgba(11,107,105,0) 70%)",
        backgroundRepeat: "no-repeat",
      }}
    >
      <TopBar v={v} />
      <Hero v={v} />
      <HowItWorks v={v} />
      <Explore v={v} />
      <Evidence v={v} />
      <Output v={v} />
      <WhyItExists v={v} />
      <GetStarted v={v} />
      <Footer v={v} />
    </div>
  );
}
