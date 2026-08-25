"use client";

import { useEffect, useState } from "react";
import { apiClient } from "@/lib/apiClient";
import { Activity, ShieldCheck, Cpu, Database, Network } from "lucide-react";

interface HealthStatus {
  status: string;
  service: string;
  version: string;
  environment: string;
}

export default function HomePage() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function checkHealth() {
      try {
        setLoading(true);
        const res = await apiClient.get<HealthStatus>("/health");
        setHealth(res.data);
        setError(null);
      } catch (err: any) {
        setError(err?.message || "Failed to reach backend API");
      } finally {
        setLoading(false);
      }
    }
    checkHealth();
  }, []);

  return (
    <main className="min-h-screen bg-[#090d16] text-slate-100 p-8 flex flex-col items-center justify-center relative overflow-hidden">
      {/* Background Neon Gradients */}
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-[128px] pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-purple-500/10 rounded-full blur-[128px] pointer-events-none" />

      <div className="max-w-3xl w-full z-10 space-y-8">
        {/* Header Branding */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-xs font-mono tracking-wider">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            SENTRIX IDS CORE
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight text-white sm:text-5xl">
            Autonomous Intrusion Detection & Calibrated Response
          </h1>
          <p className="text-slate-400 text-base max-w-xl mx-auto">
            Real-time multi-signal fusion combining PyTorch autoencoder anomaly scoring, XGBoost confidence margins, statistical drift monitoring, and automated SDN containment.
          </p>
        </div>

        {/* System Health Card */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur-xl shadow-2xl space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                <Activity className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">System Status</h2>
                <p className="text-xs text-slate-400 font-mono">Backend API connectivity check</p>
              </div>
            </div>
            <div>
              {loading ? (
                <span className="px-2.5 py-1 rounded-md text-xs font-mono bg-slate-800 text-slate-400 animate-pulse">
                  Connecting...
                </span>
              ) : health?.status === "ok" ? (
                <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  STATUS: OK
                </span>
              ) : (
                <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-red-500/10 text-red-400 border border-red-500/30">
                  OFFLINE
                </span>
              )}
            </div>
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
            <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-2 text-slate-400 text-xs font-medium">
                <ShieldCheck className="h-4 w-4 text-cyan-400" />
                Service
              </div>
              <p className="text-sm font-semibold text-white font-mono">
                {health?.service || "Sentrix Core"}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-2 text-slate-400 text-xs font-medium">
                <Cpu className="h-4 w-4 text-purple-400" />
                Version
              </div>
              <p className="text-sm font-semibold text-white font-mono">
                {health?.version || "0.1.0"}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-2 text-slate-400 text-xs font-medium">
                <Network className="h-4 w-4 text-emerald-400" />
                Environment
              </div>
              <p className="text-sm font-semibold text-white font-mono">
                {health?.environment || "Development"}
              </p>
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-mono">
              Connection notice: {error}
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
