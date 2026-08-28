"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Search,
  RefreshCw,
  SlidersHorizontal,
  Code,
  X,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { DashboardShell } from "@/components/layout/DashboardShell";
import { apiClient } from "@/lib/apiClient";

interface FlowItem {
  id: string;
  captured_at: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packet_count: number;
  byte_count: number;
  duration: number;
}

export default function FlowExplorerPage() {
  const [srcIp, setSrcIp] = useState("");
  const [dstIp, setDstIp] = useState("");
  const [protocol, setProtocol] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 25;

  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);
  const [copiedJson, setCopiedJson] = useState(false);

  const { data, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ["flows", srcIp, dstIp, protocol, page],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (srcIp) params.append("src_ip", srcIp);
      if (dstIp) params.append("dst_ip", dstIp);
      if (protocol) params.append("protocol", protocol);
      params.append("limit", pageSize.toString());
      params.append("offset", (page * pageSize).toString());

      const res = await apiClient.get(`/api/v1/flows?${params.toString()}`);
      return res.data;
    },
  });

  const { data: flowDetail, isLoading: isDetailLoading } = useQuery({
    queryKey: ["flow-detail", selectedFlowId],
    queryFn: async () => {
      if (!selectedFlowId) return null;
      const res = await apiClient.get(`/api/v1/flows/${selectedFlowId}`);
      return res.data;
    },
    enabled: !!selectedFlowId,
  });

  const flows: FlowItem[] = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.ceil(total / pageSize);

  const copyJson = () => {
    if (flowDetail) {
      navigator.clipboard.writeText(JSON.stringify(flowDetail, null, 2));
      setCopiedJson(true);
      setTimeout(() => setCopiedJson(false), 2000);
    }
  };

  return (
    <DashboardShell>
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Search className="w-6 h-6 text-cyan-400" />
            Forensic Flow Explorer
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Deep packet inspection and multi-parameter network flow database search.
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

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <div>
          <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Source IP
          </label>
          <input
            type="text"
            placeholder="e.g. 10.0.0.45"
            value={srcIp}
            onChange={(e) => {
              setSrcIp(e.target.value);
              setPage(0);
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div>
          <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Destination IP
          </label>
          <input
            type="text"
            placeholder="e.g. 192.168.10.50"
            value={dstIp}
            onChange={(e) => {
              setDstIp(e.target.value);
              setPage(0);
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div>
          <label className="block text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Protocol
          </label>
          <select
            value={protocol}
            onChange={(e) => {
              setProtocol(e.target.value);
              setPage(0);
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>

        <div className="flex items-end">
          <button
            onClick={() => {
              setSrcIp("");
              setDstIp("");
              setProtocol("");
              setPage(0);
            }}
            className="w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Flows Table */}
      <div className="rounded-2xl bg-slate-900/80 border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
              <tr>
                <th className="py-3.5 px-4">Captured At</th>
                <th className="py-3.5 px-4">Source Endpoint</th>
                <th className="py-3.5 px-4">Destination Endpoint</th>
                <th className="py-3.5 px-4">Protocol</th>
                <th className="py-3.5 px-4">Packets</th>
                <th className="py-3.5 px-4">Bytes</th>
                <th className="py-3.5 px-4">Duration</th>
                <th className="py-3.5 px-4 text-right">Telemetry</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-sans">
                    Searching flow archives...
                  </td>
                </tr>
              ) : flows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-sans">
                    No flows matched query filters.
                  </td>
                </tr>
              ) : (
                flows.map((flow) => (
                  <tr
                    key={flow.id}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                      {new Date(flow.captured_at).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
                    </td>
                    <td className="py-3.5 px-4 text-cyan-400">
                      {flow.src_ip}:{flow.src_port}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px]">
                        {flow.protocol}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300">{flow.packet_count}</td>
                    <td className="py-3.5 px-4 text-slate-300">{flow.byte_count} B</td>
                    <td className="py-3.5 px-4 text-slate-400">{flow.duration.toFixed(3)}s</td>
                    <td className="py-3.5 px-4 text-right font-sans">
                      <button
                        onClick={() => setSelectedFlowId(flow.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs transition-colors"
                      >
                        <Code className="w-3.5 h-3.5" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {flows.length > 0 ? page * pageSize + 1 : 0} to{" "}
            {Math.min((page + 1) * pageSize, total)} of {total} flows
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="p-1.5 rounded bg-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-700"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>
              Page {page + 1} of {Math.max(1, totalPages)}
            </span>
            <button
              onClick={() => setPage((p) => (p + 1 < totalPages ? p + 1 : p))}
              disabled={page + 1 >= totalPages}
              className="p-1.5 rounded bg-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-700"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Raw 71-Feature JSON Telemetry Modal */}
      {selectedFlowId && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[80vh] flex flex-col shadow-2xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Code className="w-4 h-4 text-cyan-400" />
                <span>Raw Flow Vector Telemetry</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={copyJson}
                  className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs flex items-center gap-1"
                >
                  {copiedJson ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  <span>{copiedJson ? "Copied" : "Copy"}</span>
                </button>
                <button
                  onClick={() => setSelectedFlowId(null)}
                  className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="p-4 overflow-y-auto flex-1 font-mono text-[11px] text-slate-300 bg-slate-950/60 leading-relaxed">
              {isDetailLoading ? (
                <div className="text-center py-12 text-slate-500">Loading flow vector...</div>
              ) : (
                <pre>{JSON.stringify(flowDetail, null, 2)}</pre>
              )}
            </div>
          </div>
        </div>
      )}
    </DashboardShell>
  );
}
