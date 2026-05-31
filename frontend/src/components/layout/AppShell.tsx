import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { T } from "../../lib/designTokens";

export function AppShell({
  children,
  activeView,
  setActiveView,
}: {
  children: ReactNode;
  activeView: string;
  setActiveView: (view: string) => void;
}) {
  return (
    <div style={{ display: "flex", height: "100vh", background: T.bg0, color: T.text0, fontFamily: "'IBM Plex Sans', sans-serif", overflow: "hidden" }}>
      <Sidebar activeView={activeView} setActiveView={setActiveView} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <TopBar />
        {children}
      </div>
    </div>
  );
}
