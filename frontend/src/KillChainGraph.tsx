import { useEffect, useRef } from "react";
import * as d3 from "d3";

type Props = {
  stages: string[];
  active: string;
  prevented: string[];
  onSelect: (stage: string) => void;
};

export function KillChainGraph({ stages, active, prevented, onSelect }: Props) {
  const ref = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const width = ref.current.clientWidth || 700;
    const height = 340;
    const svg = d3.select(ref.current);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const x = d3.scalePoint<string>().domain(stages).range([60, width - 40]);
    const y = height / 2;

    const links = stages.slice(0, -1).map((s, i) => ({ a: s, b: stages[i + 1] }));
    svg
      .selectAll("line.link")
      .data(links)
      .enter()
      .append("line")
      .attr("class", "link")
      .attr("x1", (d) => x(d.a)!)
      .attr("y1", y)
      .attr("x2", (d) => x(d.b)!)
      .attr("y2", y);

    const nodes = svg
      .selectAll("g.node-wrap")
      .data(stages)
      .enter()
      .append("g")
      .attr("transform", (d) => `translate(${x(d)},${y})`)
      .style("cursor", "pointer")
      .on("click", (_, d) => onSelect(d));

    nodes
      .append("rect")
      .attr("class", (d) => (d === active ? "node active" : "node"))
      .attr("x", -54)
      .attr("y", -18)
      .attr("width", 108)
      .attr("height", 36)
      .attr("opacity", (d) => (prevented.includes(d) ? 0.35 : 1));

    nodes
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 5)
      .attr("fill", "#14161a")
      .style("font-size", "11px")
      .style("font-family", "IBM Plex Mono, monospace")
      .text((d) => d);

    nodes
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dy", 40)
      .attr("fill", "#5c6570")
      .style("font-size", "10px")
      .text((d) => (prevented.includes(d) ? "prevented" : ""));
  }, [stages, active, prevented, onSelect]);

  return <svg className="graph" ref={ref} />;
}
