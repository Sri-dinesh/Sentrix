"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  Search,
  TrendingUp,
  ShieldAlert,
  Sliders,
  Sparkles,
} from "lucide-react";
import { useCurrentUserRole } from "@/lib/useCurrentUserRole";

export function Sidebar() {
  const pathname = usePathname();
  const { isAdmin } = useCurrentUserRole();

  const navItems = [
    {
      name: "Live Monitor",
      href: "/",
      icon: Activity,
      exact: true,
    },
    {
      name: "Incidents & Playbooks",
      href: "/incidents",
      icon: AlertTriangle,
    },
    {
      name: "Forensic Flow Explorer",
      href: "/flows",
      icon: Search,
    },
    {
      name: "Concept Drift Studio",
      href: "/drift",
      icon: TrendingUp,
    },
    {
      name: "Containment Center",
      href: "/containment",
      icon: ShieldAlert,
    },
    {
      name: "Settings & Models",
      href: "/settings",
      icon: Sliders,
      adminOnly: true,
    },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-[#090d16]/90 p-4 flex flex-col justify-between shrink-0 min-h-[calc(100vh-4rem)]">
      {/* Main Nav Links */}
      <nav className="space-y-1.5">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          SOC Operations
        </div>

        {navItems.map((item) => {
          const isActive = item.exact
            ? pathname === item.href
            : pathname.startsWith(item.href);

          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.1)]"
                  : "text-slate-300 hover:text-white hover:bg-slate-900/80"
              }`}
            >
              <div className="flex items-center gap-3">
                <item.icon
                  className={`w-4 h-4 ${
                    isActive ? "text-cyan-400" : "text-slate-400"
                  }`}
                />
                <span>{item.name}</span>
              </div>
              {item.adminOnly && (
                <span
                  className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded font-semibold ${
                    isAdmin
                      ? "bg-purple-950 text-purple-400 border border-purple-800/60"
                      : "bg-slate-800 text-slate-400"
                  }`}
                >
                  Admin
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Autonomous Guard Card */}
      <div className="p-3.5 rounded-xl bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-800 space-y-2">
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold">
          <Sparkles className="w-4 h-4" />
          <span>Active Learning Engine</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Autonomous threat containment with continuous Bayesian drift calibration.
        </p>
        <div className="pt-1 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <span>Model: Autoencoder v1</span>
          <span className="text-emerald-400">● Synced</span>
        </div>
      </div>
    </aside>
  );
}
