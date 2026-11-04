import { NextResponse } from 'next/server';
import { fetchFlaskBackend } from '@/lib/backendClient';

export async function POST() {
  try {
    const res = await fetchFlaskBackend('/api/admin/ml/retrain', { method: 'POST' }, 60000);
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: 'Failed to trigger ML retrain' }, { status: 502 });
  }
}
