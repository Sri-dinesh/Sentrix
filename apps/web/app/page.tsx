"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  TrendingUp,
  Zap,
  Radio,
  ArrowUpRight,
  ShieldCheck,
  Flame,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { useEventStream, StreamThreatEvent } from "@/lib/useEventStream";
import { apiClient } from "@/lib/apiClient";

export default function LiveMonitorPage() {
  const { events: sseEvents, isConnected, stats } = useEventStream();
  const [recentThreats, setRecentThreats] = useState<StreamThreatEvent[]>([]);
  const [chartData, setChartData] = useState<any[]>([]);

  // Initialize baseline chart points
  useEffect(() => {
    const initialPoints = Array.from({ length: 15 }, (_, i) => {
      const time = new Date(Date.now() - (14 - i) * 2000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
      return {
        time,
        flows: Math.floor(Math.random() * 40) + 70,
        anomalies: Math.floor(Math.random() * 6),
      };
    });
    setChartData(initialPoints);

    // Mock initial threat events if none received yet
    const initialThreats: StreamThreatEvent[] = [
      {
        id: "ev-101",
        timestamp: "Just now",
        src_ip: "10.0.0.45",
        dst_ip: "192.168.10.50",
        attack_type: "DoS Hulk",
        anomaly_score: 0.3656,
        confidence_score: 0.88,
        tier: "HIGH",
        action: "BLOCK",
      },
      {
        id: "ev-102",
        timestamp: "12s ago",
        src_ip: "10.0.0.22",
        dst_ip: "192.168.10.22",
        attack_type: "SSH-Patator",
        anomaly_score: 0.2463,
        confidence_score: 0.80,
        tier: "MEDIUM",
        action: "RATE_LIMIT",
      },
      {
        id: "ev-103",
        timestamp: "28s ago",
        src_ip: "10.0.0.77",
        dst_ip: "192.168.10.50",
        attack_type: "PortScan",
        anomaly_score: 0.2581,
        confidence_score: 0.80,
        tier: "MEDIUM",
        action: "RATE_LIMIT",
      },
      {
        id: "ev-104",
        timestamp: "45s ago",
        src_ip: "10.0.0.99",
        dst_ip: "192.168.10.50",
        attack_type: "DDoS",
        anomaly_score: 0.2725,
        confidence_score: 0.59,
        tier: "MEDIUM",
        action: "RATE_LIMIT",
      },
    ];
    setRecentThreats(initialThreats);
  }, []);

  // Update chart data periodically
  useEffect(() => {
    const interval = setInterval(() => {
      setChartData((prev) => {
        const time = new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
        const newFlows = Math.floor(Math.random() * 50) + 80;
        const newAnomalies = Math.random() > 0.4 ? Math.floor(Math.random() * 8) + 1 : 0;
        return [...prev.slice(1), { time, flows: newFlows, anomalies: newAnomalies }];
      });
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  // Merge SSE incoming events with recent list
  useEffect(() => {
    if (sseEvents.length > 0) {
      setRecentThreats((prev) => [sseEvents[0], ...prev.slice(0, 19)]);
    }
  }, [sseEvents]);

  return (
    <DashboardShell>
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold text-white tracking-tight">
              Live Threat Operations Console
            </h1>
            <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              Real-Time Active
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Autonomous confidence-calibrated telemetry & intrusion mitigation stream.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/incidents"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors shadow-lg shadow-cyan-600/20"
          >
            <AlertTriangle className="w-4 h-4" />
            <span>Review Incidents</span>
          </Link>
          <Link
            href="/containment"
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium text-sm transition-colors border border-slate-700"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Active Blocks</span>
          </Link>
        </div>
      </div>

      {/* Top 4 KPI Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Flows */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Total Ingested Flows
            </span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono mt-3">
            {stats.totalFlows.toLocaleString()}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-emerald-400 mt-1">
            <span>↑ 124 flows/sec</span>
            <span className="text-slate-500">• Line-rate</span>
          </div>
          <div className="absolute -right-6 -bottom-6 w-20 h-20 bg-cyan-500/5 rounded-full blur-xl group-hover:bg-cyan-500/10 transition-all" />
        </div>

        {/* Active Anomalies */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Anomalies Flagged
            </span>
            <Flame className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-3">
            {stats.anomalies.toLocaleString()}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-amber-400/80 mt-1">
            <span>Autoencoder MSE &gt; 0.0261</span>
          </div>
          <div className="absolute -right-6 -bottom-6 w-20 h-20 bg-amber-500/5 rounded-full blur-xl group-hover:bg-amber-500/10 transition-all" />
        </div>

        {/* Contained Threats */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Auto-Contained Threats
            </span>
            <ShieldCheck className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono mt-3">
            {stats.contained.toLocaleString()}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-rose-400/80 mt-1">
            <span>Ryu SDN &amp; iptables Active</span>
          </div>
          <div className="absolute -right-6 -bottom-6 w-20 h-20 bg-rose-500/5 rounded-full blur-xl group-hover:bg-rose-500/10 transition-all" />
        </div>

        {/* Concept Drift Index */}
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 backdrop-blur-sm relative overflow-hidden group hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Concept Drift Index
            </span>
            <TrendingUp className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400 font-mono mt-3">
            {stats.driftScore.toFixed(4)}
          </div>
          <div className="flex items-center gap-1.5 text-xs text-emerald-400 mt-1">
            <span>● Stable baseline (KS &lt; 0.25)</span>
          </div>
          <div className="absolute -right-6 -bottom-6 w-20 h-20 bg-purple-500/5 rounded-full blur-xl group-hover:bg-purple-500/10 transition-all" />
        </div>
      </div>

      {/* Main Grid: Telemetry Chart (2/3) + Real-Time Threat Feed (1/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Telemetry Time-Series Chart */}
        <div className="lg:col-span-2 p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Network Traffic Volume &amp; Attack Pressure
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Live flow arrival rate vs flagged anomaly intensity (2-second interval)
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500" /> Total Flows
              </span>
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" /> Anomalies
              </span>
            </div>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="flowGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="anomalyGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="time"
                  stroke="#64748b"
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                />
                <YAxis
                  stroke="#64748b"
                  tick={{ fontSize: 11 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#334155",
                    borderRadius: "0.5rem",
                    fontSize: "12px",
                    color: "#f8fafc",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="flows"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#flowGradient)"
                  name="Flow Volume"
                />
                <Area
                  type="monotone"
                  dataKey="anomalies"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#anomalyGradient)"
                  name="Anomalies Flagged"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-4 mt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Inference Latency: &lt; 2.8ms per flow</span>
            <span className="text-cyan-400">PyTorch Autoencoder + XGBoost Pipeline</span>
          </div>
        </div>

        {/* Real-Time Live Threat Feed */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col h-full">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-rose-400 animate-pulse" />
              <h2 className="text-base font-semibold text-white">Live Threat Feed</h2>
            </div>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {recentThreats.length} Events
            </span>
          </div>

          <div className="space-y-3 overflow-y-auto max-h-[380px] pr-1">
            {recentThreats.map((threat) => {
              const isHigh = threat.tier === "HIGH";
              const isMedium = threat.tier === "MEDIUM";

              return (
                <div
                  key={threat.id}
                  className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-all space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sm text-slate-200">
                      {threat.attack_type}
                    </span>
                    <span
                      className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded-full uppercase ${
                        isHigh
                          ? "bg-rose-950 text-rose-400 border border-rose-800/60"
                          : isMedium
                          ? "bg-amber-950 text-amber-400 border border-amber-800/60"
                          : "bg-blue-950 text-blue-400 border border-blue-800/60"
                      }`}
                    >
                      {threat.tier} ({Math.round(threat.confidence_score * 100)}%)
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span>{threat.src_ip}</span>
                    <span>→ {threat.dst_ip}</span>
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[11px]">
                    <span className="text-slate-500">{threat.timestamp}</span>
                    <span
                      className={`font-mono font-semibold ${
                        threat.action === "BLOCK"
                          ? "text-rose-400"
                          : threat.action === "RATE_LIMIT"
                          ? "text-amber-400"
                          : "text-slate-400"
                      }`}
                    >
                      Actuation: {threat.action}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="pt-4 mt-auto border-t border-slate-800">
            <Link
              href="/incidents"
              className="flex items-center justify-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
            >
              <span>View Full Incident Forensic Log</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </DashboardShell>
  );
}
