import { PayPalAgentToolkit } from "@paypal/agent-toolkit/ai-sdk";

const clientId = process.env.PAYPAL_CLIENT_ID || "";
const clientSecret = process.env.PAYPAL_CLIENT_SECRET || "";

let paypalToolkit = null;
let paypalTools = null;

try {
  if (clientId && clientSecret && clientId !== "YOUR_SANDBOX_CLIENT_ID_HERE") {
    paypalToolkit = new PayPalAgentToolkit({
      clientId,
      clientSecret,
      context: {
        sandbox: true,
      },
    });

    paypalTools = paypalToolkit.getTools();
    console.log("[PayPal Toolkit] Initialized successfully in Sandbox mode.");
  } else {
    console.warn("[PayPal Toolkit] Credentials not fully configured in .env. Initializing in sandbox standby.");
  }
} catch (err) {
  console.warn("[PayPal Toolkit Init Warning]:", err.message);
}

export { paypalToolkit, paypalTools };
