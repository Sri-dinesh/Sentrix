import type { Metadata } from "next";
import { ClerkProvider } from "@clerk/nextjs";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentrix | Autonomous Calibrated Intrusion Detection & Threat Containment",
  description:
    "Self-learning network intrusion detection with autonomous, confidence-calibrated threat containment, concept drift monitoring, and LLM playbooks.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <ClerkProvider
      appearance={{
        variables: {
          colorPrimary: "#06b6d4",
          colorBackground: "#0f172a",
        },
      }}
    >
      <html lang="en" className="dark">
        <body className="bg-[#090d16] text-slate-100 antialiased min-h-screen">
          {children}
        </body>
      </html>
    </ClerkProvider>
  );
}
