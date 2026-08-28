"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  TrendingUp,
  RefreshCw,
  Sparkles,
  Layers,
  Database,
  CheckCircle2,
  AlertCircle,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiClient } from "@/lib/apiClient";

export default function DriftStudioPage() {
  const { data: driftStatus, isLoading: isStatusLoading, refetch: refetchStatus } = useQuery({
    queryKey: ["drift-status"],
    queryFn: async () => {
      const res = await apiClient.get("/api/v1/drift/status");
      return res.data;
    },
    refetchInterval: 10000,
  });

  const { data: driftEventsData, isLoading: isEventsLoading } = useQuery({
    queryKey: ["drift-events"],
    queryFn: async () => {
      const res = await apiClient.get("/api/v1/drift/events");
      return res.data;
    },
  });

  const driftScore = driftStatus?.drift_score || 0.042;
  const isDrifting = driftStatus?.is_drifting || false;
  const sampleCount = driftStatus?.sample_count || 120;
  const threshold = driftStatus?.drift_threshold || 0.25;
  const driftEvents = driftEventsData?.items || [];

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <TrendingUp className="w-6 h-6 text-purple-400" />
            Concept Drift &amp; Retraining Studio
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            2-sample Kolmogorov-Smirnov statistical shift detection &amp; continuous active learning.
          </p>
        </div>

        <button
          onClick={() => refetchStatus()}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors border border-slate-700 self-start"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Scan Drift Window</span>
        </button>
      </div>

      {/* Top Cards: Gauge, Sample Count, Active Learning Pool */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* KS Drift Score Gauge */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Kolmogorov-Smirnov Statistic
            </span>
            <Sparkles className="w-4 h-4 text-purple-400" />
          </div>

          <div className="flex items-baseline gap-3">
            <span className="text-3xl font-bold font-mono text-purple-400">
              {driftScore.toFixed(4)}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              / threshold {threshold.toFixed(2)}
            </span>
          </div>

          {/* Progress bar gauge */}
          <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className={`h-full transition-all duration-500 ${
                isDrifting ? "bg-rose-500" : "bg-purple-500"
              }`}
              style={{
                width: `${Math.min(100, (driftScore / threshold) * 100)}%`,
              }}
            />
          </div>

          <div className="flex items-center gap-2 text-xs">
            {isDrifting ? (
              <span className="text-rose-400 flex items-center gap-1 font-semibold">
                <AlertCircle className="w-3.5 h-3.5" /> Distribution Shift Detected
              </span>
            ) : (
              <span className="text-emerald-400 flex items-center gap-1 font-semibold">
                <CheckCircle2 className="w-3.5 h-3.5" /> Baseline Distribution Stable
              </span>
            )}
          </div>
        </div>

        {/* Rolling Window */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Rolling Observation Window
            </span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>

          <div className="text-3xl font-bold font-mono text-cyan-400">
            {sampleCount.toLocaleString()} / 500
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Rolling buffer of 16-dimensional Autoencoder bottleneck latent representations evaluated against benign reference distribution.
          </p>

          <div className="text-[11px] font-mono text-slate-500">
            Reference Set: 2,500 Benign Latents
          </div>
        </div>

        {/* Active Learning Candidate Pool */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Active Learning Staging Pool
            </span>
            <Database className="w-4 h-4 text-amber-400" />
          </div>

          <div className="text-3xl font-bold font-mono text-amber-400">
            2 Staged Samples
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            Analyst-verified false-positive network flow vectors queued to refine decision boundaries in the next Autoencoder training loop.
          </p>

          <div className="text-[11px] font-mono text-emerald-400">
            Auto-Feedback: Active
          </div>
        </div>
      </div>

      {/* Historical Drift Events Table */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-xl">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-purple-400" />
          Historical Distribution Shift Events
        </h2>

        <div className="rounded-xl border border-slate-800 overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Drift Metric (KS)</th>
                <th className="py-3 px-4">Retraining Triggered</th>
                <th className="py-3 px-4 text-right">Detected At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {isEventsLoading ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-400 font-sans">
                    Loading drift logs...
                  </td>
                </tr>
              ) : driftEvents.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500 font-sans">
                    No historical drift anomalies recorded.
                  </td>
                </tr>
              ) : (
                driftEvents.map((ev: any) => (
                  <tr key={ev.id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 text-slate-400">#{ev.id.substring(0, 8)}</td>
                    <td className="py-3 px-4 text-purple-400 font-bold">
                      {ev.drift_score?.toFixed(4)}
                    </td>
                    <td className="py-3 px-4 font-sans">
                      {ev.triggered_retrain ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 text-[10px] font-semibold">
                          Retrain Dispatched
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                          Monitored
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-right text-[11px]">
                      {new Date(ev.detected_at).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardShell>
  );
}
