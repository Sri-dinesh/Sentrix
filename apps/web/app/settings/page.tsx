"use client";

import React, { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Sliders,
  ShieldCheck,
  Save,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Sparkles,
  Zap,
  Check,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { useCurrentUserRole } from "@/lib/useCurrentUserRole";
import { apiClient } from "@/lib/apiClient";

export default function SettingsPage() {
  const { isAdmin, role } = useCurrentUserRole();
  const queryClient = useQueryClient();

  const [w1, setW1] = useState(0.4);
  const [w2, setW2] = useState(0.4);
  const [w3, setW3] = useState(0.2);
  const [tierHigh, setTierHigh] = useState(0.85);
  const [tierMed, setTierMed] = useState(0.5);
  const [anomalyThreshold, setAnomalyThreshold] = useState(0.026147);
  const [successMsg, setSuccessMsg] = useState("");

  const { data: settingsData, isLoading: isSettingsLoading } = useQuery({
    queryKey: ["settings"],
    queryFn: async () => {
      const res = await apiClient.get("/api/v1/settings");
      return res.data;
    },
  });

  const { data: modelsData, isLoading: isModelsLoading } = useQuery({
    queryKey: ["models"],
    queryFn: async () => {
      const res = await apiClient.get("/api/v1/models");
      return res.data;
    },
  });

  useEffect(() => {
    if (settingsData) {
      setW1(settingsData.confidence_weight_anomaly ?? 0.4);
      setW2(settingsData.confidence_weight_classifier ?? 0.4);
      setW3(settingsData.confidence_weight_drift ?? 0.2);
      setTierHigh(settingsData.tier_high_threshold ?? 0.85);
      setTierMed(settingsData.tier_medium_threshold ?? 0.5);
      setAnomalyThreshold(settingsData.anomaly_base_threshold ?? 0.026147);
    }
  }, [settingsData]);

  const updateSettingsMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.put("/api/v1/settings", {
        confidence_weight_anomaly: w1,
        confidence_weight_classifier: w2,
        confidence_weight_drift: w3,
        tier_high_threshold: tierHigh,
        tier_medium_threshold: tierMed,
        anomaly_base_threshold: anomalyThreshold,
      });
      return res.data;
    },
    onSuccess: () => {
      setSuccessMsg("Confidence weights and response thresholds updated successfully!");
      queryClient.invalidateQueries({ queryKey: ["settings"] });
      setTimeout(() => setSuccessMsg(""), 4000);
    },
  });

  const activateModelMutation = useMutation({
    mutationFn: async (versionId: string) => {
      const res = await apiClient.post(`/api/v1/models/${versionId}/activate`);
      return res.data;
    },
    onSuccess: () => {
      setSuccessMsg("Model promoted to active production checkpoint!");
      queryClient.invalidateQueries({ queryKey: ["models"] });
      setTimeout(() => setSuccessMsg(""), 4000);
    },
  });

  const weightSum = +(w1 + w2 + w3).toFixed(2);
  const isWeightValid = Math.abs(weightSum - 1.0) < 0.01;
  const models = modelsData?.items || [];

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Sliders className="w-6 h-6 text-cyan-400" />
            System Tuning &amp; Model Registry
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Calibrate confidence fusion weights, response tier actuation, and model versions.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {!isAdmin ? (
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-950/80 text-amber-300 border border-amber-800/60 text-xs">
              <AlertTriangle className="w-4 h-4" />
              <span>Read-Only Mode ({role})</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/80 text-purple-300 border border-purple-800/60 text-xs font-semibold">
              <ShieldCheck className="w-4 h-4" />
              <span>Administrator Access</span>
            </div>
          )}
        </div>
      </div>

      {successMsg && (
        <div className="p-3 rounded-xl bg-emerald-950/80 border border-emerald-800/80 text-emerald-300 text-xs flex items-center gap-2 font-medium">
          <CheckCircle2 className="w-4 h-4" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Grid: Confidence Weights + Response Tiers */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Card 1: Multi-Signal Confidence Formula Tuning */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-5 shadow-xl">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <h2 className="text-base font-bold text-white">
                Multi-Signal Confidence Formula
              </h2>
            </div>
            <span
              className={`text-xs font-mono px-2 py-0.5 rounded ${
                isWeightValid
                  ? "bg-emerald-950 text-emerald-300 border border-emerald-800/60"
                  : "bg-rose-950 text-rose-300 border border-rose-800/60"
              }`}
            >
              Sum: {weightSum.toFixed(2)} / 1.00
            </span>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 font-mono text-[11px] text-slate-300 text-center">
            Confidence = clip( {w1.toFixed(2)}·MSE + {w2.toFixed(2)}·Margin - {w3.toFixed(2)}·Drift, 0.0, 1.0 )
          </div>

          <div className="space-y-4 text-xs">
            {/* Weight 1 */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>w1: Autoencoder Reconstruction MSE Weight</span>
                <span className="font-mono text-cyan-400 font-bold">{w1.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="1.0"
                step="0.05"
                disabled={!isAdmin}
                value={w1}
                onChange={(e) => setW1(parseFloat(e.target.value))}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* Weight 2 */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>w2: XGBoost Classifier Margin Weight</span>
                <span className="font-mono text-cyan-400 font-bold">{w2.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="1.0"
                step="0.05"
                disabled={!isAdmin}
                value={w2}
                onChange={(e) => setW2(parseFloat(e.target.value))}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* Weight 3 */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>w3: Concept Drift Penalty Weight</span>
                <span className="font-mono text-rose-400 font-bold">{w3.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="1.0"
                step="0.05"
                disabled={!isAdmin}
                value={w3}
                onChange={(e) => setW3(parseFloat(e.target.value))}
                className="w-full accent-rose-400"
              />
            </div>
          </div>
        </div>

        {/* Card 2: Autonomous Response Tier Thresholds */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-5 shadow-xl">
          <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
            <Zap className="w-4 h-4 text-amber-400" />
            <h2 className="text-base font-bold text-white">
              Autonomous Response Tier Cutoffs
            </h2>
          </div>

          <div className="space-y-4 text-xs">
            {/* Tier High */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Tier HIGH (Autonomous DROP Block)</span>
                <span className="font-mono text-rose-400 font-bold">&ge; {tierHigh.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.60"
                max="0.99"
                step="0.01"
                disabled={!isAdmin}
                value={tierHigh}
                onChange={(e) => setTierHigh(parseFloat(e.target.value))}
                className="w-full accent-rose-400"
              />
            </div>

            {/* Tier Medium */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Tier MEDIUM (Rate-Limiting Meter)</span>
                <span className="font-mono text-amber-400 font-bold">&ge; {tierMed.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.20"
                max="0.80"
                step="0.01"
                disabled={!isAdmin}
                value={tierMed}
                onChange={(e) => setTierMed(parseFloat(e.target.value))}
                className="w-full accent-amber-400"
              />
            </div>

            {/* Anomaly Cutoff */}
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Autoencoder Anomaly MSE Threshold</span>
                <span className="font-mono text-purple-400 font-bold">{anomalyThreshold.toFixed(6)}</span>
              </div>
              <input
                type="number"
                step="0.001"
                disabled={!isAdmin}
                value={anomalyThreshold}
                onChange={(e) => setAnomalyThreshold(parseFloat(e.target.value))}
                className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono"
              />
            </div>

            {isAdmin && (
              <div className="pt-2">
                <button
                  onClick={() => updateSettingsMutation.mutate()}
                  disabled={updateSettingsMutation.isPending || !isWeightValid}
                  className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-bold transition-colors flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/20"
                >
                  <Save className="w-4 h-4" />
                  <span>
                    {updateSettingsMutation.isPending
                      ? "Saving Settings..."
                      : "Save & Invalidate Cache"}
                  </span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Model Versions Registry */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-xl">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">
              Model Version Registry &amp; Checkpoints
            </h2>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Component</th>
                <th className="py-3 px-4">Version Tag</th>
                <th className="py-3 px-4">Storage Checkpoint Path</th>
                <th className="py-3 px-4">Validation Metrics</th>
                <th className="py-3 px-4">Production Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {isModelsLoading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400 font-sans">
                    Loading model checkpoints...
                  </td>
                </tr>
              ) : models.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500 font-sans">
                    No models registered in Supabase storage yet.
                  </td>
                </tr>
              ) : (
                models.map((m: any) => (
                  <tr key={m.id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 capitalize text-slate-200 font-sans font-semibold">
                      {m.component}
                    </td>
                    <td className="py-3 px-4 text-cyan-400 font-bold">{m.version_tag}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">{m.storage_path}</td>
                    <td className="py-3 px-4 text-slate-300 text-[11px]">
                      {m.metrics ? JSON.stringify(m.metrics) : "-"}
                    </td>
                    <td className="py-3 px-4 font-sans">
                      {m.is_active ? (
                        <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/50 text-[10px] font-bold">
                          Active Production
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Inactive</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      {!m.is_active && isAdmin && (
                        <button
                          onClick={() => activateModelMutation.mutate(m.id)}
                          disabled={activateModelMutation.isPending}
                          className="px-2.5 py-1 rounded bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600 hover:text-white transition-colors text-xs font-semibold"
                        >
                          Promote
                        </button>
                      )}
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
