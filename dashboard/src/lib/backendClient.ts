/**
 * Shared backend fetch helper for Next.js API route proxies.
 * Handles SERVICE_API_KEY header and tries target URLs in order.
 */

const DEFAULT_SERVICE_KEY = 'REDACTED_SERVICE_API_KEY';

export async function fetchFlaskBackend(path: string, options: RequestInit = {}): Promise<Response> {
  const serviceApiKey = process.env.SERVICE_API_KEY || DEFAULT_SERVICE_KEY;

  const targetUrls = Array.from(new Set([
    process.env.NEXT_PUBLIC_API_URL,
    'http://127.0.0.1:5000',
    'http://localhost:5000',
    'http://flask_api:5000'
  ])).filter(Boolean) as string[];

  let lastError: Error | null = null;

  const headers = new Headers(options.headers || {});
  if (!headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${serviceApiKey}`);
  }

  for (const baseUrl of targetUrls) {
    try {
      const url = `${baseUrl}${path.startsWith('/') ? path : '/' + path}`;
      const res = await fetch(url, {
        ...options,
        headers,
        cache: 'no-store'
      });
      if (res) {
        return res;
      }
    } catch (err: any) {
      lastError = err;
    }
  }

  throw lastError || new Error(`Failed to connect to Flask backend at ${path}`);
}
