export function RecommendationList({ items }: { items: string[] }) {
  return (
    <ul className="mt-4 space-y-2">
      {items.map((item) => (
        <li key={item} className="rounded-md bg-slate-50 px-3 py-2 text-sm text-slate-700">
          {item}
        </li>
      ))}
    </ul>
  );
}
