"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Plus,
  Unlock,
  CheckCircle2,
  AlertOctagon,
  Network,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiClient } from "@/lib/apiClient";

export default function ContainmentPage() {
  const queryClient = useQueryClient();
  const [targetIp, setTargetIp] = useState("");
  const [actionType, setActionType] = useState("BLOCK");
  const [feedbackMsg, setFeedbackMsg] = useState("");

  const { data, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ["containment-active"],
    queryFn: async () => {
      const res = await apiClient.get("/api/v1/containment/active");
      return res.data;
    },
    refetchInterval: 5000,
  });

  const blockMutation = useMutation({
    mutationFn: async ({ ip, action }: { ip: string; action: string }) => {
      const res = await apiClient.post("/api/v1/containment/block", {
        src_ip: ip,
        action: action,
      });
      return res.data;
    },
    onSuccess: (resData) => {
      setFeedbackMsg(`Successfully applied ${resData.action} to ${resData.src_ip} via ${resData.actuator}!`);
      setTargetIp("");
      queryClient.invalidateQueries({ queryKey: ["containment-active"] });
      setTimeout(() => setFeedbackMsg(""), 4000);
    },
  });

  const unblockMutation = useMutation({
    mutationFn: async (ip: string) => {
      const res = await apiClient.post("/api/v1/containment/unblock", {
        src_ip: ip,
      });
      return res.data;
    },
    onSuccess: (resData) => {
      setFeedbackMsg(`Successfully lifted containment for ${resData.src_ip}!`);
      queryClient.invalidateQueries({ queryKey: ["containment-active"] });
      setTimeout(() => setFeedbackMsg(""), 4000);
    },
  });

  const blockedIps: string[] = data?.active_blocked_ips || [];
  const history = data?.recent_actions || [];

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-rose-500" />
            Autonomous Threat Containment Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Ryu OpenFlow 1.3 SDN switch rule enforcement and Linux Netfilter/iptables host defense.
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

      {feedbackMsg && (
        <div className="p-3 rounded-xl bg-emerald-950/80 border border-emerald-800/80 text-emerald-300 text-xs flex items-center gap-2 font-medium">
          <CheckCircle2 className="w-4 h-4" />
          <span>{feedbackMsg}</span>
        </div>
      )}

      {/* Manual Trigger + Engine Status Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Manual Enforcement Form */}
        <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <Plus className="w-4 h-4 text-cyan-400" />
            <span>Manual Containment Enforcement</span>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (targetIp) {
                blockMutation.mutate({ ip: targetIp, action: actionType });
              }
            }}
            className="space-y-3"
          >
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Target Source IP
              </label>
              <input
                type="text"
                required
                placeholder="e.g. 10.0.0.99"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Containment Action
              </label>
              <select
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="BLOCK">DROP Flow (Block)</option>
                <option value="RATE_LIMIT">Throttling Meter (Rate Limit)</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={blockMutation.isPending || !targetIp}
              className="w-full py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors shadow-md shadow-rose-600/20"
            >
              {blockMutation.isPending ? "Applying Rule..." : "Enforce Containment"}
            </button>
          </form>
        </div>

        {/* Actuator Status Cards */}
        <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  OpenFlow 1.3 SDN Controller
                </span>
                <Network className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-xl font-bold text-white">Ryu REST Client</div>
              <p className="text-xs text-slate-400">
                Programs line-rate flow tables on DPID switch hardware at priority 65535.
              </p>
            </div>
            <div className="pt-4 flex items-center justify-between text-xs border-t border-slate-800">
              <span className="text-slate-400">Default Target: DPID 1</span>
              <span className="text-cyan-400 font-mono">REST:8080</span>
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Host Perimeter Firewall
                </span>
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-xl font-bold text-white">Netfilter iptables</div>
              <p className="text-xs text-slate-400">
                Fallback and local host packet filtering driver for standalone deployments.
              </p>
            </div>
            <div className="pt-4 flex items-center justify-between text-xs border-t border-slate-800">
              <span className="text-slate-400">INPUT Chain Filter</span>
              <span className="text-emerald-400 font-mono">Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Actively Contained IPs Table */}
      <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-xl">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-5 h-5 text-rose-500" />
            <h2 className="text-base font-bold text-white">
              Currently Contained IP Addresses
            </h2>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            {blockedIps.length} Active Leases
          </span>
        </div>

        <div className="rounded-xl border border-slate-800 overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Contained Source IP</th>
                <th className="py-3 px-4">Scope</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-400 font-sans">
                    Loading contained IP leases...
                  </td>
                </tr>
              ) : blockedIps.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500 font-sans">
                    No IP addresses currently under containment.
                  </td>
                </tr>
              ) : (
                blockedIps.map((ip) => (
                  <tr key={ip} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-bold text-rose-400">{ip}</td>
                    <td className="py-3 px-4 font-sans text-slate-300">
                      SDN Switch &amp; iptables INPUT
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 text-[10px] font-semibold">
                        DROP Active
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => unblockMutation.mutate(ip)}
                        disabled={unblockMutation.isPending}
                        className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
                      >
                        <Unlock className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Release Rule</span>
                      </button>
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
