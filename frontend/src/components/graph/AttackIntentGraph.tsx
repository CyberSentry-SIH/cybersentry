'use client';

import React, { useState, useCallback, useMemo } from 'react';
import { GraphNode, GraphEdge } from '@/types/api';
import {
  ZoomIn,
  ZoomOut,
  RefreshCw,
  Maximize2,
  Minimize2,
  Radar,
  Link2,
  X
} from 'lucide-react';

interface AttackIntentGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const NODE_CONFIG: Record<string, { fill: string; stroke: string; label: string; icon: string; glow: string }> = {
  EMAIL:     { fill: '#1e293b', stroke: '#38bdf8', label: '#e2e8f0', icon: '✉️', glow: 'rgba(56, 189, 248, 0.4)' },
  SENDER:    { fill: '#3b0764', stroke: '#c084fc', label: '#f3e8ff', icon: '👤', glow: 'rgba(192, 132, 252, 0.4)' },
  DOMAIN:    { fill: '#451a03', stroke: '#fbbf24', label: '#fef3c7', icon: '🌐', glow: 'rgba(251, 191, 36, 0.4)' },
  URL:       { fill: '#4c0519', stroke: '#f43f5e', label: '#ffe4e6', icon: '🔗', glow: 'rgba(244, 63, 94, 0.4)' },
  IP:        { fill: '#082f49', stroke: '#0ea5e9', label: '#e0f2fe', icon: '🖥️', glow: 'rgba(14, 165, 233, 0.4)' },
  INTENT:    { fill: '#4a044e', stroke: '#e879f9', label: '#fae8ff', icon: '🎯', glow: 'rgba(232, 121, 249, 0.4)' },
  CAMPAIGN:  { fill: '#064e3b', stroke: '#34d399', label: '#ecfdf5', icon: '⚡', glow: 'rgba(52, 211, 153, 0.4)' },
  RECIPIENT: { fill: '#1e293b', stroke: '#94a3b8', label: '#f1f5f9', icon: '📥', glow: 'rgba(148, 163, 184, 0.4)' },
  ATTACHMENT:{ fill: '#312e81', stroke: '#818cf8', label: '#e0e7ff', icon: '📎', glow: 'rgba(129, 140, 248, 0.4)' },
};

function getNodeConfig(type: string) {
  return NODE_CONFIG[type] || { fill: '#1e293b', stroke: '#64748b', label: '#cbd5e1', icon: '⚪', glow: 'rgba(100, 116, 139, 0.3)' };
}

export default function AttackIntentGraph({ nodes, edges }: AttackIntentGraphProps) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [scale, setScale] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [activeFilter, setActiveFilter] = useState<string>('ALL');

  // Spacious canvas dimensions
  const W = 1100, H = 680;

  // Filter nodes based on selected type filter
  const visibleNodes = useMemo(() => {
    if (activeFilter === 'ALL') return nodes;
    return nodes.filter(n => n.node_type === activeFilter || n.node_type === 'EMAIL');
  }, [nodes, activeFilter]);

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map(n => n.id)), [visibleNodes]);

  const visibleEdges = useMemo(() => {
    return edges.filter(e => visibleNodeIds.has(e.from_node) && visibleNodeIds.has(e.to_node));
  }, [edges, visibleNodeIds]);

  // Spacious radial layout with distinct rings and wide angular separation
  const nodePositions = useMemo(() => {
    const posMap: Record<string, { x: number; y: number }> = {};
    const cx = W / 2, cy = H / 2;

    const emailNode = visibleNodes.find(n => n.node_type === 'EMAIL');
    if (emailNode) posMap[emailNode.id] = { x: cx, y: cy };

    const byType: Record<string, GraphNode[]> = {};
    visibleNodes.filter(n => n.node_type !== 'EMAIL').forEach(n => {
      byType[n.node_type] = byType[n.node_type] || [];
      byType[n.node_type].push(n);
    });

    const rings = [
      ['SENDER', 'DOMAIN'],
      ['INTENT', 'CAMPAIGN'],
      ['URL', 'ATTACHMENT'],
      ['IP', 'RECIPIENT'],
    ];
    // Generous radii for clean spacing
    const radii = [170, 260, 350, 430];

    rings.forEach((group, ringIdx) => {
      const nodesInRing: GraphNode[] = [];
      group.forEach(t => (byType[t] || []).forEach(n => nodesInRing.push(n)));
      nodesInRing.forEach((node, i) => {
        const total = Math.max(1, nodesInRing.length);
        const angle = (i / total) * 2 * Math.PI - Math.PI / 2;
        const r = radii[ringIdx] || 320;
        posMap[node.id] = {
          x: cx + r * Math.cos(angle),
          y: cy + r * Math.sin(angle),
        };
      });
    });

    // Uncategorized / remaining nodes
    const placed = new Set(Object.keys(posMap));
    const remaining = visibleNodes.filter(n => !placed.has(n.id));
    remaining.forEach((node, i) => {
      const angle = (i / Math.max(1, remaining.length)) * 2 * Math.PI;
      posMap[node.id] = { x: cx + 320 * Math.cos(angle), y: cy + 320 * Math.sin(angle) };
    });

    return posMap;
  }, [visibleNodes, W, H]);

  const zoom = useCallback((dir: 1 | -1) => {
    setScale(s => Math.min(2.5, Math.max(0.35, s + dir * 0.15)));
  }, []);

  const resetView = useCallback(() => {
    setScale(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
    setSelectedEdge(null);
  }, []);

  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).tagName === 'svg' || (e.target as HTMLElement).tagName === 'rect') {
      setDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragging) return;
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
  };

  const handleMouseUp = () => setDragging(false);

  // Available node types in this graph
  const availableTypes = useMemo(() => {
    const types = new Set(nodes.map(n => n.node_type));
    types.delete('EMAIL');
    return Array.from(types);
  }, [nodes]);

  return (
    <div className={`relative rounded-2xl border border-slate-300 dark:border-slate-700/80 bg-white dark:bg-slate-900 shadow-xl overflow-hidden flex flex-col transition-colors duration-200 ${isFullscreen ? 'fixed inset-4 z-50' : 'w-full'}`}>
      {/* TOP CONTROLS & FILTER BAR */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/90 dark:bg-slate-900/90 backdrop-blur-xl z-10">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-100 dark:bg-cyan-950/80 border border-cyan-300 dark:border-cyan-800/80 text-cyan-800 dark:text-cyan-400 text-xs font-mono font-bold">
            <Radar className="h-3.5 w-3.5" />
            <span>Interactive Attack Graph</span>
          </div>
          <span className="text-xs text-slate-500 dark:text-slate-400 font-mono hidden sm:inline">
            {visibleNodes.length} Entities • {visibleEdges.length} Relations
          </span>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setActiveFilter('ALL')}
            className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
              activeFilter === 'ALL'
                ? 'bg-cyan-600 text-white font-bold'
                : 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
            }`}
          >
            All Types
          </button>
          {availableTypes.map(t => (
            <button
              key={t}
              onClick={() => setActiveFilter(t)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold transition-colors cursor-pointer ${
                activeFilter === t
                  ? 'bg-cyan-600 text-white font-bold'
                  : 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Viewport Action Buttons */}
        <div className="flex items-center gap-1.5 bg-slate-200/80 dark:bg-slate-800/80 p-1 rounded-lg border border-slate-300 dark:border-slate-700">
          <button
            onClick={() => zoom(1)}
            className="p-1.5 rounded hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
            title="Zoom In"
          >
            <ZoomIn className="h-4 w-4" />
          </button>
          <button
            onClick={() => zoom(-1)}
            className="p-1.5 rounded hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
            title="Zoom Out"
          >
            <ZoomOut className="h-4 w-4" />
          </button>
          <button
            onClick={resetView}
            className="p-1.5 rounded hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
            title="Reset View"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-1.5 rounded hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors cursor-pointer"
            title="Toggle Fullscreen"
          >
            {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* SVG CANVAS AREA */}
      <div
        className="relative flex-1 w-full bg-[#f4f7fb] dark:bg-[#111a2c] overflow-hidden cursor-grab active:cursor-grabbing transition-colors duration-200"
        style={{ minHeight: isFullscreen ? 'calc(100vh - 180px)' : '620px' }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
      >
        {/* Background Grid Lines */}
        <svg
          className="w-full h-full absolute inset-0"
          style={{ pointerEvents: 'none' }}
        >
          <defs>
            <pattern id="graph-grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(100, 116, 139, 0.15)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#graph-grid)" />
        </svg>

        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="w-full h-full relative z-0"
        >
          <defs>
            {/* Arrowhead markers */}
            <marker
              id="arrow-cyan"
              viewBox="0 0 10 10"
              refX="28"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#0284c7" />
            </marker>
            <marker
              id="arrow-selected"
              viewBox="0 0 10 10"
              refX="28"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
            </marker>

            {/* Glow Filters */}
            <filter id="glow-selected" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* TRANSFORM GROUP (PAN & SCALE) */}
          <g transform={`translate(${pan.x + (1 - scale) * (W / 2)}, ${pan.y + (1 - scale) * (H / 2)}) scale(${scale})`}>
            {/* RADIAL GUIDELINES */}
            <circle cx={W/2} cy={H/2} r={170} fill="none" stroke="rgba(100, 116, 139, 0.1)" strokeWidth="1" strokeDasharray="4,4" />
            <circle cx={W/2} cy={H/2} r={260} fill="none" stroke="rgba(100, 116, 139, 0.1)" strokeWidth="1" strokeDasharray="4,4" />
            <circle cx={W/2} cy={H/2} r={350} fill="none" stroke="rgba(100, 116, 139, 0.08)" strokeWidth="1" strokeDasharray="4,4" />
            <circle cx={W/2} cy={H/2} r={430} fill="none" stroke="rgba(100, 116, 139, 0.06)" strokeWidth="1" strokeDasharray="4,4" />

            {/* EDGES / RELATIONSHIP LINES */}
            {visibleEdges.map(edge => {
              const src = nodePositions[edge.from_node];
              const dst = nodePositions[edge.to_node];
              if (!src || !dst) return null;

              const isEdgeSelected = selectedEdge?.id === edge.id;
              const isConnectedToSelected = selectedNode && (edge.from_node === selectedNode.id || edge.to_node === selectedNode.id);

              const strokeColor = isEdgeSelected
                ? '#f59e0b'
                : isConnectedToSelected
                ? '#06b6d4'
                : 'rgba(100, 116, 139, 0.35)';

              const strokeWidth = isEdgeSelected ? 3 : isConnectedToSelected ? 2.5 : 1.5;

              // Midpoint for relationship label
              const midX = (src.x + dst.x) / 2;
              const midY = (src.y + dst.y) / 2;

              return (
                <g key={edge.id} className="cursor-pointer" onClick={() => { setSelectedEdge(edge); setSelectedNode(null); }}>
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={dst.x}
                    y2={dst.y}
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeDasharray={edge.relation === 'CORRELATED_WITH' ? '6,4' : undefined}
                    markerEnd={isEdgeSelected ? 'url(#arrow-selected)' : 'url(#arrow-cyan)'}
                    className="transition-all duration-200"
                  />
                  {/* Small relationship pill tag on hover/selected */}
                  {(isEdgeSelected || isConnectedToSelected) && edge.relation && (
                    <g transform={`translate(${midX}, ${midY})`}>
                      <rect
                        x="-36"
                        y="-10"
                        width="72"
                        height="20"
                        rx="4"
                        fill="#0f172a"
                        stroke={strokeColor}
                        strokeWidth="1"
                      />
                      <text
                        x="0"
                        y="3"
                        textAnchor="middle"
                        fill="#f8fafc"
                        fontSize="9"
                        fontFamily="monospace"
                        fontWeight="600"
                      >
                        {edge.relation.replace('_', ' ')}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {/* NODES */}
            {visibleNodes.map(node => {
              const pos = nodePositions[node.id];
              if (!pos) return null;

              const cfg = getNodeConfig(node.node_type);
              const isNodeSelected = selectedNode?.id === node.id;
              const isCenter = node.node_type === 'EMAIL';
              const r = isCenter ? 26 : 20;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  className="cursor-pointer group"
                  onClick={() => { setSelectedNode(node); setSelectedEdge(null); }}
                >
                  {/* Pulse glow circle on selected */}
                  {isNodeSelected && (
                    <circle
                      r={r + 8}
                      fill="none"
                      stroke="#06b6d4"
                      strokeWidth="2"
                      className="animate-pulse"
                    />
                  )}

                  {/* Outer glow ring */}
                  <circle
                    r={r + 3}
                    fill="none"
                    stroke={cfg.stroke}
                    strokeWidth={isNodeSelected ? 3 : 1.5}
                    strokeOpacity={isNodeSelected ? 1 : 0.6}
                  />

                  {/* Main Node Body */}
                  <circle
                    r={r}
                    fill={cfg.fill}
                    filter={isNodeSelected ? 'url(#glow-selected)' : undefined}
                    className="transition-transform duration-200 group-hover:scale-110"
                  />

                  {/* Icon Emoji */}
                  <text
                    x="0"
                    y="5"
                    textAnchor="middle"
                    fontSize={isCenter ? '14' : '11'}
                    className="select-none pointer-events-none"
                  >
                    {cfg.icon}
                  </text>

                  {/* Text Label Below Node */}
                  <g transform={`translate(0, ${r + 14})`}>
                    <rect
                      x={-Math.min(90, Math.max(30, (node.label.length * 5.5) / 2))}
                      y="-8"
                      width={Math.min(180, Math.max(60, node.label.length * 5.5))}
                      height="16"
                      rx="4"
                      fill="rgba(15, 23, 42, 0.85)"
                      stroke={isNodeSelected ? '#06b6d4' : 'rgba(51, 65, 85, 0.5)'}
                      strokeWidth="0.75"
                    />
                    <text
                      x="0"
                      y="3"
                      textAnchor="middle"
                      fill="#f8fafc"
                      fontSize="9.5"
                      fontFamily="monospace"
                      fontWeight="600"
                      className="select-none pointer-events-none"
                    >
                      {node.label.length > 22 ? `${node.label.substring(0, 20)}…` : node.label}
                    </text>
                  </g>
                </g>
              );
            })}
          </g>
        </svg>

        {/* SIDE DRAWER: SELECTED NODE INSPECTION */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-84 rounded-2xl border border-slate-300 dark:border-slate-700 bg-white/95 dark:bg-slate-900/95 p-5 backdrop-blur-2xl shadow-2xl z-20 animate-fade-in text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800 mb-3">
              <div className="flex items-center gap-2">
                <span className="text-base">{getNodeConfig(selectedNode.node_type).icon}</span>
                <span className="font-mono font-bold text-slate-900 dark:text-white uppercase">{selectedNode.node_type}</span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 rounded-md text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase">Entity Label</span>
                <p className="font-bold text-slate-900 dark:text-white text-sm break-words mt-0.5">{selectedNode.label}</p>
              </div>

              {selectedNode.value && (
                <div>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase">Canonical Value</span>
                  <p className="font-mono text-cyan-700 dark:text-cyan-300 break-all bg-slate-100 dark:bg-slate-950 p-2 rounded border border-slate-200 dark:border-slate-800 mt-0.5">
                    {selectedNode.value}
                  </p>
                </div>
              )}

              {selectedNode.metadata_json && Object.keys(selectedNode.metadata_json).length > 0 && (
                <div>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase">Metadata Attributes</span>
                  <div className="bg-slate-100 dark:bg-slate-950 p-2 rounded border border-slate-200 dark:border-slate-800 mt-0.5 space-y-1 font-mono text-[11px]">
                    {Object.entries(selectedNode.metadata_json).map(([k, v]) => (
                      <div key={k} className="flex justify-between">
                        <span className="text-slate-500 dark:text-slate-400">{k}:</span>
                        <span className="text-slate-800 dark:text-slate-200">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* SIDE DRAWER: SELECTED EDGE INSPECTION */}
        {selectedEdge && !selectedNode && (
          <div className="absolute top-4 right-4 w-80 rounded-2xl border border-slate-300 dark:border-slate-700 bg-white/95 dark:bg-slate-900/95 p-5 backdrop-blur-2xl shadow-2xl z-20 animate-fade-in text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800 mb-3">
              <div className="flex items-center gap-2">
                <Link2 className="h-4 w-4 text-cyan-600 dark:text-cyan-400" />
                <span className="font-mono font-bold text-slate-900 dark:text-white uppercase">Relationship Link</span>
              </div>
              <button
                onClick={() => setSelectedEdge(null)}
                className="p-1 rounded-md text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase">Relationship Type</span>
                <p className="font-bold text-cyan-700 dark:text-cyan-300 font-mono mt-0.5">{selectedEdge.relation}</p>
              </div>

              <div>
                <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase">Confidence / Weight</span>
                <p className="font-mono text-slate-800 dark:text-slate-200 mt-0.5">
                  {typeof selectedEdge.confidence === 'number' ? (selectedEdge.confidence * 100).toFixed(1) + '%' : (selectedEdge.evidence_strength || '100%')}
                </p>
              </div>

              {selectedEdge.evidence && Object.keys(selectedEdge.evidence).length > 0 && (
                <div>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 uppercase">Edge Evidence</span>
                  <div className="bg-slate-100 dark:bg-slate-950 p-2 rounded border border-slate-200 dark:border-slate-800 mt-0.5 space-y-1 font-mono text-[11px]">
                    {Object.entries(selectedEdge.evidence).map(([k, v]) => (
                      <div key={k} className="flex justify-between">
                        <span className="text-slate-500 dark:text-slate-400">{k}:</span>
                        <span className="text-slate-800 dark:text-slate-200">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* BOTTOM LEGEND BAR */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-900/80 text-[11px] font-mono">
        <div className="flex flex-wrap items-center gap-4 text-slate-600 dark:text-slate-400">
          <span className="text-slate-500 dark:text-slate-500 uppercase tracking-wider font-bold">Legend:</span>
          {Object.entries(NODE_CONFIG).map(([type, cfg]) => (
            <div key={type} className="flex items-center gap-1.5">
              <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cfg.stroke }} />
              <span className="text-slate-700 dark:text-slate-300">{type}</span>
            </div>
          ))}
        </div>
        <span className="text-slate-500 dark:text-slate-500 hidden md:inline">
          Drag to Pan • Scroll/Controls to Zoom • Click Node to Inspect
        </span>
      </div>
    </div>
  );
}
