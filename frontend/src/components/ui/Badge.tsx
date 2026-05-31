import type { ReactNode } from "react";

const tones: Record<string, string> = {
  critical: "bg-rose-100 text-rose-700 border-rose-200",
  high: "bg-orange-100 text-orange-700 border-orange-200",
  medium: "bg-amber-100 text-amber-700 border-amber-200",
  low: "bg-emerald-100 text-emerald-700 border-emerald-200",
};

export function Badge({ children, tone = "low" }: { children: ReactNode; tone?: string }) {
  return (
    <span className={`inline-flex h-7 items-center rounded-md border px-2 text-xs font-semibold ${tones[tone] || tones.low}`}>
      {children}
    </span>
  );
}
