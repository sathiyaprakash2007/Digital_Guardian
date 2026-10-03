import { NextResponse } from 'next/server'

import { classifyScreenshot, scanHistory } from '../../../lib/scan-store'

export async function POST(request: Request) {
  const form = await request.formData()
  const image = form.get('image')

  const isValidImage = !!image && typeof image === 'object' && 'arrayBuffer' in image && typeof (image as File).name === 'string'

  if (!isValidImage) {
    return NextResponse.json({ detail: 'Image is required.' }, { status: 400 })
  }

  const file = image as File
  return NextResponse.json(classifyScreenshot(file.name, file.size))
}

export function GET() {
  return NextResponse.json(scanHistory)
}
