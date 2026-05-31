import type { ReactNode } from "react";

export function Card({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">{children}</div>;
}
