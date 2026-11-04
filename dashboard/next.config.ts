import os from "os";
import type { NextConfig } from "next";

const localInterfaceIps = Object.values(os.networkInterfaces())
  .flat()
  .map((iface) => iface?.address)
  .filter((addr): addr is string => Boolean(addr));

const extraOrigins = (
  process.env.ALLOWED_ORIGINS ||
  process.env.NEXT_PUBLIC_BASE_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  ""
)
  .split(",")
  .map((item) => {
    try {
      return new URL(item.trim()).hostname;
    } catch {
      return item.trim();
    }
  })
  .filter(Boolean);

const nextConfig: NextConfig = {
  allowedDevOrigins: Array.from(
    new Set([
      "localhost",
      "127.0.0.1",
      "*.ts.net",
      ...localInterfaceIps,
      ...extraOrigins,
    ])
  ),
};

export default nextConfig;
