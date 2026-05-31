import { RiskBadge } from "../analysis/RiskBadge";

export function CriticalPaths({
  paths,
}: {
  paths: Array<{ title: string; path: string; risk: string; detail: string }>;
}) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-sm font-semibold text-slate-900">Critical Paths</h2>
      <div className="mt-4 grid gap-3">
        {paths.map((item) => (
          <div key={item.title} className="rounded-md border border-slate-200 p-3">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <h3 className="text-sm font-semibold text-slate-900">{item.title}</h3>
              <RiskBadge level={item.risk} />
            </div>
            <p className="mt-2 font-mono text-xs text-slate-500">{item.path}</p>
            <p className="mt-2 text-sm text-slate-600">{item.detail}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
