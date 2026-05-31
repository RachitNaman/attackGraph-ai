import { Server } from "lucide-react";

export function AttackSurface() {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-center gap-2">
        <Server className="h-4 w-4 text-slate-500" />
        <h2 className="text-sm font-semibold text-slate-900">Attack Surface</h2>
      </div>
      <div className="mt-4 space-y-3">
        {["web-server-01", "vpn-gateway-01", "jump-server-01"].map((host) => (
          <div key={host} className="rounded-md border border-slate-200 p-3">
            <div className="text-sm font-semibold text-slate-800">{host}</div>
            <div className="mt-1 text-xs text-slate-500">Internet-facing host</div>
          </div>
        ))}
      </div>
    </section>
  );
}
