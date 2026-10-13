// One call to the Claude Messages API with a JSON schema, so the page always gets the same fields back.

export const DEFAULT_MODEL = 'claude-sonnet-5-5';

export async function callClaude({ model, system, user, schema, maxTokens, timeoutMs = 50000 }) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw Object.assign(new Error('ANTHROPIC_API_KEY is not set'), { reachedClaude: false });

  let res;
  try {
    res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        system,
        messages: [{ role: 'user', content: user }],
        output_config: { format: { type: 'json_schema', schema } },
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    // A timeout may still have been billed, so the caller settles at the reserved amount.
    throw Object.assign(new Error(`Claude request failed: ${err.name}`), { reachedClaude: 'unknown' });
  }

  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = body?.error?.type || res.status;
    throw Object.assign(new Error(`Claude API returned ${res.status} (${detail})`), { reachedClaude: false, status: res.status });
  }
  if (body.stop_reason === 'refusal') {
    throw Object.assign(new Error('Claude declined this request'), { reachedClaude: true, usage: body.usage });
  }
  if (body.stop_reason === 'max_tokens') {
    throw Object.assign(new Error('The answer ran past the length limit'), { reachedClaude: true, usage: body.usage });
  }
  const text = body.content?.find((b) => b.type === 'text')?.text;
  return { data: JSON.parse(text), usage: body.usage, model: body.model || model, requestId: res.headers.get('request-id') || body.id || null };
}

export function obj(properties, required = Object.keys(properties)) {
  return { type: 'object', properties, required, additionalProperties: false };
}
