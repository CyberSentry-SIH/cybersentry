export function Sparkline({
  data,
  className,
  strokeClassName = "stroke-accent-primary",
}: {
  data: number[];
  className?: string;
  strokeClassName?: string;
}) {
  if (data.length < 2) return null;

  const width = 64;
  const height = 20;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;

  const points = data.map((value, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((value - min) / range) * height;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className={className}
      width={width}
      height={height}
      aria-hidden="true"
    >
      <polyline
        points={points.join(" ")}
        fill="none"
        strokeWidth={1.5}
        className={strokeClassName}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
