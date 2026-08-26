"use client";

import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@clerk/nextjs";
import { apiClient } from "./apiClient";

export interface CurrentUserProfile {
  id: string;
  clerk_user_id: string;
  email: string;
  role: "analyst" | "admin" | string;
  created_at: string;
}

export function useCurrentUserRole() {
  const { isLoaded, isSignedIn, getToken } = useAuth();

  const query = useQuery({
    queryKey: ["currentUserProfile"],
    queryFn: async (): Promise<CurrentUserProfile> => {
      const token = await getToken();
      const response = await apiClient.get<CurrentUserProfile>("/api/v1/me", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      return response.data;
    },
    enabled: isLoaded && !!isSignedIn,
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: 2,
  });

  const role = query.data?.role || "analyst";
  const isAdmin = role === "admin";
  const isAnalyst = role === "analyst";

  return {
    ...query,
    user: query.data,
    role,
    isAdmin,
    isAnalyst,
    isLoading: !isLoaded || query.isLoading,
  };
}
