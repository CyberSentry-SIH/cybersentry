import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    let raw = (
      process.env.NEXT_PUBLIC_API_URL ||
      process.env.BACKEND_URL ||
      "https://cybersentry-backend-egmb.onrender.com/api/v1"
    ).trim();

    // Normalize protocol
    if (!raw.startsWith("http://") && !raw.startsWith("https://")) {
      raw = `https://${raw}`;
    }

    // Handle bare service names on Render (e.g. 'cybersentry-backend-egmb')
    const urlWithoutProto = raw.replace(/^https?:\/\//, "");
    if (!urlWithoutProto.includes(".") && !urlWithoutProto.includes("localhost") && !urlWithoutProto.includes("127.0.0.1")) {
      const parts = raw.split("://");
      const pathIndex = parts[1].indexOf("/");
      if (pathIndex === -1) {
        raw = `${parts[0]}://${parts[1]}.onrender.com`;
      } else {
        raw = `${parts[0]}://${parts[1].slice(0, pathIndex)}.onrender.com${parts[1].slice(pathIndex)}`;
      }
    }

    const backendOrigin = raw.replace(/\/api\/v1\/?$/, "");

    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendOrigin}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;

