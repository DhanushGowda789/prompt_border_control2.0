# Sovereign Shield

Sovereign Shield is a local AI privacy firewall. API requests to supported cloud AI endpoints are inspected by the local classifier before they are forwarded. Sensitive requests are routed to Ollama on the same device instead of the cloud.

## Run

1. Install Node.js 18+.
2. Install Ollama and start it with `ollama serve`.
3. Pull a local model, for example `ollama pull llama3.2`.
4. From `proxy/`, run `npm install` (or use the included `node_modules` directory) and then `npm start`.
5. Open `http://localhost:3334` for the dashboard.
6. Load `extension/` as an unpacked Chrome/Chromium extension.

Optional model pinning:

```bash
OLLAMA_MODEL=llama3.2 npm start
```

## Dashboard

The dashboard is served by the proxy and uses the same classifier/configuration as the interception path. It includes live activity, a prompt test panel, sensitivity/category controls, monitored-app controls, local-model status, and history.

## Safety behavior

If the proxy cannot be reached, the browser integration fails closed rather than silently falling back to a direct cloud request. This prevents a proxy outage from bypassing the privacy boundary.

## Supported cloud API hosts

- `api.openai.com`
- `api.anthropic.com`
- `generativelanguage.googleapis.com`
