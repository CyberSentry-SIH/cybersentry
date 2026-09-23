import type { Metadata } from "next";
import { Geist, Geist_Mono, Source_Serif_4 } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const sourceSerif = Source_Serif_4({
  variable: "--font-source-serif",
  subsets: ["latin"],
  weight: ["500", "600", "700"],
});

import { ThemeProvider } from "@/components/theme/theme-provider";

export const metadata: Metadata = {
  title: "CyberSentry | Email Forensic & Campaign Intelligence",
  description:
    "AI-assisted email forensic and campaign intelligence platform for SOC and government cyber-defense teams.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} ${sourceSerif.variable} h-full antialiased dark`}
    >
      <body className="min-h-full flex flex-col bg-bg-base text-text-primary">
        <ThemeProvider>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}
