// Asks Claude through the Anthropic API with the user's own API key, for
// those who choose it instead of the AI model in VS Code. The key comes from
// VS Code's secret storage; it is never written to settings or files.
// These models accept fallbacks: "default", which re-runs a request on
// another model if a safety classifier wrongly declines it, so a false
// positive does not end the explanation.
const FALLBACK_DEFAULT = new Set(['claude-opus-5-5', 'claude-opus-5', 'claude-sonnet-5-5', 'claude-fable-5-1']);

// ask sends the prompt and returns the reply text. Errors come back as
// messages a user can act on, never as the raw API error.
async function ask({ apiKey, model, prompt }) {
  // Loaded only when someone uses Anthropic, so the extension starts as
  // before for everyone else.
  const sdk = require('@anthropic-ai/sdk');
  const Anthropic = sdk.default || sdk;
  const client = new Anthropic({ apiKey });

  const body = {
    model,
    max_tokens: 16000,
    // A short explanation and one fixed excerpt; medium effort is enough.
    output_config: { effort: 'medium' },
    messages: [{ role: 'user', content: prompt }],
  };
  let response;
  try {
    response = FALLBACK_DEFAULT.has(model)
      ? await client.beta.messages.create({ ...body, betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' }, { timeout: 180_000 })
      : await client.messages.create(body, { timeout: 180_000 });
  } catch (err) {
    throw new Error(explainError(err, Anthropic));
  }

  if (response.stop_reason === 'refusal') {
    throw new Error('Claude declined to answer this one. This can happen with security-related code; try again, or read the finding\'s own explanation.');
  }
  const text = response.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
  if (!text.trim()) throw new Error('Claude returned an empty answer. Try again.');
  return { text, served: response.model || model };
}

// explainError turns API errors into plain advice, most specific first.
function explainError(err, Anthropic) {
  if (err instanceof Anthropic.AuthenticationError) {
    return 'the Anthropic API key was not accepted. Set a new one with the command "LookFirst: Set Anthropic API Key".';
  }
  if (err instanceof Anthropic.PermissionDeniedError) {
    return 'this API key may not use the chosen model. Check the key\'s workspace in the Anthropic Console, or choose another model in the setting lookFirst.ai.model.';
  }
  if (err instanceof Anthropic.RateLimitError) {
    return 'Anthropic says to slow down (rate limit). Wait a minute and try again.';
  }
  if (err instanceof Anthropic.BadRequestError) {
    return `Anthropic did not accept the request: ${err.message}. If it mentions your credit balance, add credits in the Anthropic Console.`;
  }
  if (err instanceof Anthropic.APIConnectionError) {
    return 'could not reach Anthropic. Check the internet connection and try again.';
  }
  if (err instanceof Anthropic.APIError) {
    return `Anthropic answered with an error (${err.status}): ${err.message}`;
  }
  return err && err.message ? err.message : String(err);
}

module.exports = { ask };
