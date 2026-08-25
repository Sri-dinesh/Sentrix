import axios from "axios";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 10000,
});

/**
 * Attaches a dynamic bearer token getter to axios requests
 */
export function setAuthTokenGetter(getToken: () => Promise<string | null>) {
  apiClient.interceptors.request.use(
    async (config) => {
      try {
        const token = await getToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
      } catch (err) {
        console.error("Failed to retrieve auth token for request", err);
      }
      return config;
    },
    (error) => Promise.reject(error)
  );
}

export default apiClient;
