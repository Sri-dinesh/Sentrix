"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ShieldAlert,
  Search,
  Filter,
  ArrowUpRight,
  RefreshCw,
  Clock,
  ShieldCheck,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiClient } from "@/lib/apiClient";

interface IncidentListItem {
  id: string;
  created_at: string;
  resolved_at: string | null;
  status: string;
  action_taken: string;
  mitre_technique_id: string | null;
  mitre_technique?: {
    id: string;
    name: string;
    tactic: string;
  };
  detection?: {
    id: string;
    attack_type: string;
    confidence_score: number;
    anomaly_score: number;
  };
  flow?: {
    id: string;
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: string;
  };
}

export default function IncidentsListPage() {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const {
    data,
    isLoading,
    refetch,
    isRefetching,
  } = useQuery({
    queryKey: ["incidents", statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusFilter) params.append("status", statusFilter);
      const res = await apiClient.get(`/api/v1/incidents?${params.toString()}`);
      return res.data;
    },
  });

  const incidents: IncidentListItem[] = data?.items || [];
  const filteredIncidents = incidents.filter((inc) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      inc.detection?.attack_type.toLowerCase().includes(q) ||
      inc.flow?.src_ip.toLowerCase().includes(q) ||
      inc.mitre_technique_id?.toLowerCase().includes(q)
    );
  });

  const statuses = [
    { label: "All Incidents", value: "" },
    { label: "Open", value: "open" },
    { label: "Investigating", value: "investigating" },
    { label: "Contained", value: "contained" },
    { label: "Resolved", value: "resolved" },
    { label: "False Positive", value: "false_positive" },
  ];

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <AlertTriangle className="w-6 h-6 text-rose-500" />
            Security Incidents &amp; AI Playbooks
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Automated threat triage, MITRE ATT&amp;CK correlation, and interactive containment workflows.
          </p>
        </div>

        <button
          onClick={() => refetch()}
          disabled={isRefetching}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium transition-colors border border-slate-700 self-start"
        >
          <RefreshCw className={`w-4 h-4 ${isRefetching ? "animate-spin" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filters & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        {/* Status Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
          {statuses.map((st) => (
            <button
              key={st.value}
              onClick={() => setStatusFilter(st.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                statusFilter === st.value
                  ? "bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20"
                  : "bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700"
              }`}
            >
              {st.label}
            </button>
          ))}
        </div>

        {/* Search Box */}
        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search attack, IP, MITRE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Incidents Table */}
      <div className="rounded-2xl bg-slate-900/80 border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="py-3.5 px-4">Threat Classification</th>
                <th className="py-3.5 px-4">Endpoints</th>
                <th className="py-3.5 px-4">MITRE Technique</th>
                <th className="py-3.5 px-4">Confidence</th>
                <th className="py-3.5 px-4">Action Taken</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Detected At</th>
                <th className="py-3.5 px-4 text-right">Investigation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-sans">
                    Loading security incidents...
                  </td>
                </tr>
              ) : filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                    No matching incidents found.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => {
                  const conf = inc.detection?.confidence_score || 0;
                  const isHigh = conf >= 0.85;
                  const isMed = conf >= 0.50 && conf < 0.85;

                  return (
                    <tr
                      key={inc.id}
                      className="hover:bg-slate-800/40 transition-colors group"
                    >
                      {/* Classification */}
                      <td className="py-3.5 px-4 font-sans font-semibold text-slate-200">
                        {inc.detection?.attack_type || "Network Anomaly"}
                      </td>

                      {/* Endpoints */}
                      <td className="py-3.5 px-4 text-slate-300">
                        <div>
                          <span className="text-cyan-400">{inc.flow?.src_ip}</span>
                          <span className="text-slate-500">:{inc.flow?.src_port}</span>
                        </div>
                        <div className="text-[11px] text-slate-500">
                          → {inc.flow?.dst_ip}:{inc.flow?.dst_port}
                        </div>
                      </td>

                      {/* MITRE */}
                      <td className="py-3.5 px-4">
                        {inc.mitre_technique_id ? (
                          <span className="px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800/50 text-[11px]">
                            {inc.mitre_technique_id}
                          </span>
                        ) : (
                          <span className="text-slate-500">-</span>
                        )}
                      </td>

                      {/* Confidence */}
                      <td className="py-3.5 px-4">
                        <span
                          className={`font-bold ${
                            isHigh
                              ? "text-rose-400"
                              : isMed
                              ? "text-amber-400"
                              : "text-blue-400"
                          }`}
                        >
                          {(conf * 100).toFixed(0)}%
                        </span>
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                            inc.action_taken === "BLOCK"
                              ? "bg-rose-950 text-rose-300 border border-rose-800/50"
                              : inc.action_taken === "RATE_LIMIT"
                              ? "bg-amber-950 text-amber-300 border border-amber-800/50"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {inc.action_taken}
                        </span>
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4 font-sans">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] capitalize font-medium ${
                            inc.status === "open"
                              ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                              : inc.status === "investigating"
                              ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                              : inc.status === "contained"
                              ? "bg-purple-500/10 text-purple-400 border border-purple-500/20"
                              : inc.status === "resolved"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {inc.status.replace("_", " ")}
                        </span>
                      </td>

                      {/* Date */}
                      <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                        {new Date(inc.created_at).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        })}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right font-sans">
                        <Link
                          href={`/incidents/${inc.id}`}
                          className="inline-flex items-center gap-1 px-3 py-1 rounded-md bg-cyan-600/20 text-cyan-400 hover:bg-cyan-600 hover:text-white transition-all text-xs font-medium"
                        >
                          <span>Analyze</span>
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardShell>
  );
}
