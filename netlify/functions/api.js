import serverless from "serverless-http";
import app from "../../server.js";

const expressHandler = serverless(app, {
  binary: ["application/pdf", "application/octet-stream"],
  request(req) {
    // Normalize Netlify function rewrite paths so Express sees /api/... consistently
    if (req.url && req.url.startsWith("/.netlify/functions/api")) {
      req.url = req.url.replace(/^\/\.netlify\/functions\/api/, "/api") || "/api";
    }
  },
});

export async function handler(event, context) {
  if (event?.path && event.path.startsWith("/.netlify/functions/api")) {
    event.path = event.path.replace(/^\/\.netlify\/functions\/api/, "/api") || "/api";
  }
  return expressHandler(event, context);
}

