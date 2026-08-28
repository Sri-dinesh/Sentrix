"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { UserButton } from "@clerk/nextjs";
import { Shield, Activity, ShieldCheck, RefreshCw } from "lucide-react";
import { useCurrentUserRole } from "@/lib/useCurrentUserRole";
import { apiClient } from "@/lib/apiClient";

export function Navbar() {
  const { role, isAdmin, isLoading: isRoleLoading } = useCurrentUserRole();
  const [backendHealth, setBackendHealth] = useState<"healthy" | "offline" | "checking">("checking");

  const checkHealth = async () => {
    try {
      setBackendHealth("checking");
      const res = await apiClient.get("/health");
      if (res.status === 200 && res.data.status === "healthy") {
        setBackendHealth("healthy");
      } else {
        setBackendHealth("offline");
      }
    } catch {
      setBackendHealth("offline");
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 border-b border-slate-800 bg-[#090d16]/80 backdrop-blur-md sticky top-0 z-40 px-6 flex items-center justify-between">
      {/* Brand & Status */}
      <div className="flex items-center gap-4">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg text-white tracking-wider">SENTRIX</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-semibold">
                Autonomous SOC
              </span>
            </div>
            <p className="text-[11px] text-slate-400 -mt-0.5">Confidence-Calibrated Defense</p>
          </div>
        </Link>
      </div>

      {/* Center Engine Indicator */}
      <div className="hidden md:flex items-center gap-3 bg-slate-900/60 px-3.5 py-1.5 rounded-full border border-slate-800">
        <div className="flex items-center gap-2">
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              backendHealth === "healthy"
                ? "bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.6)]"
                : backendHealth === "checking"
                ? "bg-amber-400 animate-spin"
                : "bg-rose-500"
            }`}
          />
          <span className="text-xs font-mono text-slate-300">
            {backendHealth === "healthy"
              ? "Detection Engine: ONLINE"
              : backendHealth === "checking"
              ? "Connecting..."
              : "Engine Offline"}
          </span>
        </div>
        <button
          onClick={checkHealth}
          title="Refresh Engine Health"
          className="text-slate-400 hover:text-slate-200 transition-colors"
        >
          <RefreshCw className="w-3 h-3" />
        </button>
      </div>

      {/* Right User & Role Profile */}
      <div className="flex items-center gap-4">
        {/* Role Badge */}
        {!isRoleLoading && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800">
            {isAdmin ? (
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            ) : (
              <Activity className="w-3.5 h-3.5 text-slate-400" />
            )}
            <span className="text-xs font-medium capitalize text-slate-200">{role}</span>
          </div>
        )}

        {/* Clerk User Button */}
        <div className="border border-slate-700 rounded-full p-0.5">
          <UserButton
            appearance={{
              elements: {
                avatarBox: "w-8 h-8",
              },
            }}
          />
        </div>
      </div>
    </header>
  );
}
