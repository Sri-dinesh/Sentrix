"use client";

import { useState, useEffect, useRef } from "react";

export interface StreamThreatEvent {
  id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  attack_type: string;
  anomaly_score: number;
  confidence_score: number;
  tier: "HIGH" | "MEDIUM" | "LOW";
  action: string;
}

export function useEventStream() {
  const [events, setEvents] = useState<StreamThreatEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [stats, setStats] = useState({
    totalFlows: 1420,
    anomalies: 84,
    contained: 62,
    driftScore: 0.042,
  });

  const eventSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const backendUrl =
      process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    const sseUrl = `${backendUrl}/api/v1/stream/events`;

    try {
      const es = new EventSource(sseUrl);
      eventSourceRef.current = es;

      es.onopen = () => {
        setIsConnected(true);
      };

      es.addEventListener("connected", () => {
        setIsConnected(true);
      });

      es.addEventListener("flow_detection", (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          setStats((prev) => ({
            ...prev,
            totalFlows: prev.totalFlows + 1,
            anomalies: data.is_anomalous ? prev.anomalies + 1 : prev.anomalies,
            contained:
              data.action === "BLOCK" ? prev.contained + 1 : prev.contained,
          }));

          if (data.is_anomalous) {
            const threat: StreamThreatEvent = {
              id: data.id || Math.random().toString(36).substring(7),
              timestamp: new Date().toLocaleTimeString(),
              src_ip: data.src_ip || "10.0.0.1",
              dst_ip: data.dst_ip || "192.168.10.50",
              attack_type: data.attack_type || "Anomaly",
              anomaly_score: data.anomaly_score || 0.1,
              confidence_score: data.confidence_score || 0.8,
              tier: data.tier || "MEDIUM",
              action: data.action || "RATE_LIMIT",
            };
            setEvents((prev) => [threat, ...prev.slice(0, 49)]);
          }
        } catch (err) {
          console.error("Failed to parse SSE flow event:", err);
        }
      });

      es.onerror = () => {
        setIsConnected(false);
      };

      return () => {
        es.close();
      };
    } catch {
      setIsConnected(false);
    }
  }, []);

  return { events, isConnected, stats };
}
