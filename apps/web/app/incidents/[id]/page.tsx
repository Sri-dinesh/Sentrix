"use client";

import React, { useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  Shield,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Sparkles,
  RefreshCw,
  Copy,
  Check,
  BrainCircuit,
  Terminal,
  Activity,
  Layers,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiClient } from "@/lib/apiClient";

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const incidentId = params?.id as string;
  const [copiedCmd, setCopiedCmd] = useState(false);

  const { data: incident, isLoading } = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: async () => {
      const res = await apiClient.get(`/api/v1/incidents/${incidentId}`);
      return res.data;
    },
    enabled: !!incidentId,
  });

  const updateStatusMutation = useMutation({
    mutationFn: async (newStatus: string) => {
      const res = await apiClient.patch(`/api/v1/incidents/${incidentId}/status`, {
        status: newStatus,
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
    },
  });

  const generatePlaybookMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.post(
        `/api/v1/incidents/${incidentId}/playbook/generate`
      );
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incident", incidentId] });
    },
  });

  if (isLoading) {
    return (
      <DashboardShell>
        <div className="py-24 text-center text-slate-400">
          Loading incident forensic data...
        </div>
      </DashboardShell>
    );
  }

  if (!incident) {
    return (
      <DashboardShell>
        <div className="py-24 text-center text-slate-400">
          Incident not found.
        </div>
      </DashboardShell>
    );
  }

  const det = incident.detection;
  const flow = incident.flow;
  const mt = incident.mitre_technique;
  const pb = incident.playbook;
  const breakdown = det?.confidence_breakdown;

  const copyContainmentCommand = () => {
    const cmd = `sudo iptables -I INPUT -s ${flow?.src_ip || "<IP>"} -j DROP`;
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <DashboardShell>
      {/* Back link & Top bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <Link
            href="/incidents"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold text-white tracking-tight">
                Incident #{incident.id.substring(0, 8)}
              </h1>
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-semibold capitalize ${
                  incident.status === "open"
                    ? "bg-rose-950 text-rose-300 border border-rose-800/60"
                    : incident.status === "investigating"
                    ? "bg-amber-950 text-amber-300 border border-amber-800/60"
                    : incident.status === "contained"
                    ? "bg-purple-950 text-purple-300 border border-purple-800/60"
                    : incident.status === "resolved"
                    ? "bg-emerald-950 text-emerald-300 border border-emerald-800/60"
                    : "bg-slate-800 text-slate-400"
                }`}
              >
                {incident.status.replace("_", " ")}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Detected at: {new Date(incident.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {incident.status !== "investigating" && (
            <button
              onClick={() => updateStatusMutation.mutate("investigating")}
              disabled={updateStatusMutation.isPending}
              className="px-3.5 py-1.5 rounded-lg bg-amber-600/20 text-amber-300 border border-amber-600/40 hover:bg-amber-600 hover:text-white text-xs font-semibold transition-all"
            >
              Mark Investigating
            </button>
          )}

          {incident.status !== "contained" && (
            <button
              onClick={() => updateStatusMutation.mutate("contained")}
              disabled={updateStatusMutation.isPending}
              className="px-3.5 py-1.5 rounded-lg bg-rose-600/20 text-rose-300 border border-rose-600/40 hover:bg-rose-600 hover:text-white text-xs font-semibold transition-all"
            >
              Contain Threat
            </button>
          )}

          {incident.status !== "resolved" && (
            <button
              onClick={() => updateStatusMutation.mutate("resolved")}
              disabled={updateStatusMutation.isPending}
              className="px-3.5 py-1.5 rounded-lg bg-emerald-600/20 text-emerald-300 border border-emerald-600/40 hover:bg-emerald-600 hover:text-white text-xs font-semibold transition-all flex items-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Resolve
            </button>
          )}

          {incident.status !== "false_positive" && (
            <button
              onClick={() => updateStatusMutation.mutate("false_positive")}
              disabled={updateStatusMutation.isPending}
              title="Lifts containment and stages benign sample for model retraining"
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 text-xs font-semibold transition-all"
            >
              False Positive (Auto-Unblock)
            </button>
          )}
        </div>
      </div>

      {/* Grid: Telemetry, MITRE, XAI Confidence Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Network Flow Telemetry */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
            <Activity className="w-4 h-4" />
            <span>Flow Telemetry Evidence</span>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-sans">Source Endpoint</span>
              <div className="text-cyan-400 font-bold text-sm">{flow?.src_ip}</div>
              <div className="text-slate-400">Port {flow?.src_port} ({flow?.protocol})</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-sans">Target Endpoint</span>
              <div className="text-slate-200 font-bold text-sm">{flow?.dst_ip}</div>
              <div className="text-slate-400">Port {flow?.dst_port}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-sans">Flow Volume</span>
              <div className="text-slate-200">{flow?.packet_count} packets</div>
              <div className="text-slate-400">{flow?.byte_count} bytes</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-sans">Flow Duration</span>
              <div className="text-slate-200">{flow?.duration?.toFixed(3)}s</div>
              <div className="text-emerald-400 font-sans">Captured</div>
            </div>
          </div>
        </div>

        {/* Card 2: MITRE ATT&CK Context */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-purple-400 font-semibold text-sm">
            <Layers className="w-4 h-4" />
            <span>MITRE ATT&amp;CK Context</span>
          </div>

          {mt ? (
            <div className="space-y-3 text-xs">
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 font-mono font-bold">
                    {mt.id}
                  </span>
                  <span className="font-semibold text-slate-200 text-sm">{mt.name}</span>
                </div>
                <div className="text-slate-400 text-[11px] mt-1">Tactic: {mt.tactic}</div>
              </div>
              <p className="text-slate-300 leading-relaxed text-[11px] bg-slate-950/40 p-3 rounded-lg border border-slate-800/60">
                {mt.description}
              </p>
            </div>
          ) : (
            <div className="text-xs text-slate-500">No MITRE mapping linked.</div>
          )}
        </div>

        {/* Card 3: Explainable AI Confidence Breakdown */}
        <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
            <BrainCircuit className="w-4 h-4" />
            <span>Explainable AI (XAI) Breakdown</span>
          </div>

          <div className="space-y-2.5 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Total Calibrated Confidence:</span>
              <span className="font-bold text-base font-mono text-cyan-400">
                {((det?.confidence_score || 0) * 100).toFixed(1)}%
              </span>
            </div>

            {breakdown?.components && (
              <div className="space-y-1.5 pt-2 border-t border-slate-800 font-mono text-[11px]">
                <div className="flex justify-between text-slate-300">
                  <span>+ Anomaly Weight (w1 · Anomaly):</span>
                  <span className="text-cyan-400">
                    +{breakdown.components.anomaly_contribution}
                  </span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span>+ Classifier Margin (w2 · Margin):</span>
                  <span className="text-cyan-400">
                    +{breakdown.components.classifier_contribution}
                  </span>
                </div>
                <div className="flex justify-between text-slate-300">
                  <span>- Concept Drift Penalty (w3 · Drift):</span>
                  <span className="text-rose-400">
                    -{breakdown.components.drift_penalty}
                  </span>
                </div>
              </div>
            )}

            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-[10px] text-slate-400 space-y-1">
              <div>Anomaly Score (MSE): {det?.anomaly_score?.toFixed(5)}</div>
              <div>Top-1 Margin Gap: {det?.classifier_margin?.toFixed(4)}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Card 4: AI Incident Response Playbook */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-white">
              AI Incident Containment Playbook
            </h2>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={copyContainmentCommand}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors"
            >
              {copiedCmd ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              <span>{copiedCmd ? "Copied Command!" : "Copy Containment CLI"}</span>
            </button>

            <button
              onClick={() => generatePlaybookMutation.mutate()}
              disabled={generatePlaybookMutation.isPending}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 transition-all"
            >
              <RefreshCw
                className={`w-3.5 h-3.5 ${
                  generatePlaybookMutation.isPending ? "animate-spin" : ""
                }`}
              />
              <span>
                {generatePlaybookMutation.isPending
                  ? "Generating..."
                  : "Regenerate with AI"}
              </span>
            </button>
          </div>
        </div>

        {/* Playbook Content Body */}
        {pb ? (
          <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800/80 text-slate-200 leading-relaxed text-xs space-y-4 font-sans max-h-[600px] overflow-y-auto">
            <div className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed bg-transparent">
              {pb.content}
            </div>
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 text-xs space-y-3">
            <p>No playbook generated for this incident yet.</p>
            <button
              onClick={() => generatePlaybookMutation.mutate()}
              className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-xs font-semibold hover:bg-cyan-500 transition-colors"
            >
              Generate AI Playbook
            </button>
          </div>
        )}
      </div>
    </DashboardShell>
  );
}
