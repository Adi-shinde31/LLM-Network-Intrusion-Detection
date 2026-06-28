"use client";

import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

export default function PCAChart({ data }: any) {
  const normal = data?.normal || [];
  const anomaly = data?.anomaly || [];

  return (
    <div style={{ width: "100%", height: 350 }}>
      <ResponsiveContainer>
        <ScatterChart>
          <CartesianGrid />
          <XAxis type="number" dataKey="x" name="PC1" />
          <YAxis type="number" dataKey="y" name="PC2" />
          <Tooltip cursor={{ strokeDasharray: "3 3" }} />
          <Legend />

          <Scatter name="Normal" data={normal} fill="#22c55e" />
          <Scatter name="Anomaly" data={anomaly} fill="#ef4444" />
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}