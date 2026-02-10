import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Allow reading legacy HTML files from parent directory during archive serving
  experimental: {},
  // No special output mode — run as standard Node.js server
};

export default nextConfig;
