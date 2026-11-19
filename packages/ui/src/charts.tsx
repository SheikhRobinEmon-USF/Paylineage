"use client";

import { BarChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import * as echarts from "echarts/core";
import { SVGRenderer } from "echarts/renderers";
import { useEffect, useRef } from "react";
import { compactMoney, humanize } from "./format";

echarts.use([BarChart, GridComponent, TooltipComponent, SVGRenderer]);

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}

/** Exposure held or denied, grouped by the reason that blocked it. Values are scenario exposure, not savings. */
export function ExposureByReason({ rows, label }: { rows: { code: string; minor: number; cls: "deny" | "hold" }[]; label: string }) {
  const el = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!el.current) return;
    const chart = echarts.init(el.current, undefined, { renderer: "svg" });
    const draw = () => {
      const ink = cssVar("--ink-2");
      chart.setOption({
        animationDuration: 300,
        grid: { left: 4, right: 56, top: 4, bottom: 4, containLabel: true },
        tooltip: { trigger: "item", valueFormatter: (v: unknown) => compactMoney(Number(v)) },
        xAxis: { type: "value", show: false },
        yAxis: { type: "category", data: rows.map((r) => humanize(r.code)), inverse: true, axisTick: { show: false }, axisLine: { show: false }, axisLabel: { color: ink, fontFamily: "IBM Plex Sans", fontSize: 12 } },
        series: [{
          type: "bar",
          barWidth: 12,
          data: rows.map((r) => ({ value: r.minor, itemStyle: { color: cssVar(r.cls === "deny" ? "--deny" : r.code.startsWith("SIGNAL_") ? "--untrusted" : "--hold"), borderRadius: 3 } })),
          label: { show: true, position: "right", color: ink, fontFamily: "IBM Plex Mono", fontSize: 11, formatter: (p: { value: number }) => compactMoney(p.value) },
        }],
      });
    };
    draw();
    const obs = new MutationObserver(draw);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(el.current);
    return () => {
      obs.disconnect();
      ro.disconnect();
      chart.dispose();
    };
  }, [rows]);
  return (
    <figure>
      <div ref={el} style={{ height: Math.max(80, rows.length * 26) }} role="img" aria-label={label} />
      <figcaption className="sr-only">
        {rows.map((r) => `${humanize(r.code)}: ${compactMoney(r.minor)}`).join("; ")}
      </figcaption>
    </figure>
  );
}
