import { NextResponse } from 'next/server'

import { classifyTextContent, scanHistory } from '../../../lib/scan-store'

export async function POST(request: Request) {
  let body: any = null

  try {
    body = await request.json()
  } catch {
    body = null
  }

  const text = typeof body?.text === 'string' ? body.text.trim() : ''
  const inputType = body?.input_type === 'url' || body?.input_type === 'message' ? body.input_type : 'text'

  if (!text) {
    return NextResponse.json({ detail: 'Text is required.' }, { status: 400 })
  }

  return NextResponse.json(classifyTextContent(text, inputType))
}

export function GET() {
  return NextResponse.json(scanHistory)
}
