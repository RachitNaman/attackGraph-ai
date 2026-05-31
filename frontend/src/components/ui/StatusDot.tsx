export function StatusDot({ status }: { status: "online" | "offline" | "warning" }) {
  const color = status === "online" ? "bg-emerald-500" : status === "warning" ? "bg-amber-500" : "bg-rose-500";
  return <span className={`h-2.5 w-2.5 rounded-full ${color}`} />;
}
