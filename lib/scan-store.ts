export type ThreatLevel = 'low' | 'suspicious' | 'high' | 'unknown'

export type ScanRecord = {
  id: string
  risk_score: number
  threat_level: ThreatLevel
  evidence: string[]
  recommendations: string[]
  attack_story: string[]
  input_type: 'text' | 'url' | 'message' | 'screenshot'
  analyzed_at: string
  [key: string]: unknown
}

export const scanHistory: ScanRecord[] = []

function createId() {
  return `scan-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`
}

function appendHistory(record: ScanRecord) {
  scanHistory.unshift(record)
  return record
}

export function classifyTextContent(text: string, inputType: 'text' | 'url' | 'message' = 'text'): ScanRecord {
  const normalized = text.replace(/\s+/g, ' ').trim()
  const value = normalized.toLowerCase()

  const signals = [
    /urgent|immediately|within \d+ hours?|today only|act now/.test(value) && 'Urgency language pushes the user to act quickly without thinking.',
    /password|verify your account|sign in|login|credential|account access/.test(value) && 'The content asks for credentials, account access, or sign-in activity.',
    /gift card|wire transfer|crypto|payment|bank transfer|refund/.test(value) && 'The content references payments, refunds, or high-risk financial actions.',
    /bit\.ly|tinyurl|t\.co|shorturl|goo\.gl|ow\.ly/.test(value) && 'A shortened link hides the destination and increases risk.',
    /https?:\/\//.test(value) && /@|%40/.test(value) && 'The link or message contains an unusual URL pattern that may be masking identity.',
    /from:\s*.*@|@gmail|@outlook|@icloud/.test(value) && 'The sender details resemble impersonation or an untrusted identity.',
  ].filter(Boolean) as string[]

  const score = Math.min(98, Math.max(0, signals.length * 18 + (/[a-z]/i.test(value) ? 10 : 0) + (/(https?:\/\/)/.test(value) ? 12 : 0)))
  const threat_level: ThreatLevel = score >= 70 ? 'high' : score >= 35 ? 'suspicious' : 'low'

  const record: ScanRecord = {
    id: createId(),
    risk_score: score,
    threat_level,
    evidence: signals.length ? signals : ['No obvious high-risk indicators were detected in the submitted content.'],
    recommendations:
      threat_level === 'low'
        ? ['Confirm the sender through a separate trusted channel before acting.']
        : ['Do not click links or share credentials.', 'Verify the request using an official website or contact method.', 'If a request seems urgent or payment-related, stop and confirm independently.'],
    attack_story:
      threat_level === 'low'
        ? []
        : ['A threatening message creates urgency or trust.', 'The recipient is nudged toward a risky action or credential handoff.', 'The attacker may attempt to steal access, money, or sensitive account data.'],
    input_type: inputType,
    analyzed_at: new Date().toISOString(),
  }

  return appendHistory(record)
}

export function classifyScreenshot(fileName: string, fileSize: number): ScanRecord {
  const name = fileName.toLowerCase()
  const suspiciousKeywords = ['login', 'verify', 'urgent', 'password', 'account', 'invoice', 'bank', 'security', 'alert', 'payment', 'crypto']
  const keywordHits = suspiciousKeywords.filter((word) => name.includes(word))
  const sizePenalty = fileSize > 4 * 1024 * 1024 ? 16 : fileSize > 1 * 1024 * 1024 ? 8 : 0
  const contentScore = Math.min(96, 24 + keywordHits.length * 14 + sizePenalty)
  const threat_level: ThreatLevel = contentScore >= 70 ? 'high' : contentScore >= 35 ? 'suspicious' : 'low'

  const evidence = [
    'A screenshot was uploaded for visual inspection.',
    keywordHits.length ? `The file name contains risk keywords like ${keywordHits.slice(0, 3).join(', ')}.` : 'The screenshot filename does not contain obvious phishing keywords.',
    fileSize > 2 * 1024 * 1024 ? 'The image is large enough to suggest a crafted or heavily edited security lure.' : 'The image is within a typical size range for a standard capture.',
  ]

  const record: ScanRecord = {
    id: createId(),
    risk_score: contentScore,
    threat_level,
    evidence,
    recommendations:
      threat_level === 'low'
        ? ['Treat the image as a possible social-engineering artifact until verified independently.']
        : ['Do not interact with the visual content or any linked text found in the image.', 'Check the source through a trusted channel before responding.', 'If the screenshot references login or payment actions, verify the request outside the image itself.'],
    attack_story:
      threat_level === 'low'
        ? []
        : ['The screenshot appears to be designed to create a sense of urgency or impersonation.', 'The visual may be used to redirect a user toward a harmful action or account compromise.', 'The goal is often to prompt trust before a user verifies the source.'],
    input_type: 'screenshot',
    analyzed_at: new Date().toISOString(),
  }

  return appendHistory(record)
}
