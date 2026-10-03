import { NextResponse } from 'next/server'

import { scanHistory } from '../../../lib/scan-store'

export function GET() {
  return NextResponse.json(scanHistory)
}
