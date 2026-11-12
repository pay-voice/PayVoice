/**
 * PayPal Standard Checkout Integration Client
 */

// Cart payload sent to backend
const currentCart = [
  {
    name: "Cloud API Development (Milestone 1)",
    unit_amount: "75.00",
    quantity: 1,
    currency_code: "USD",
  },
  {
    name: "DevOps Deployment & Configuration",
    unit_amount: "25.00",
    quantity: 1,
    currency_code: "USD",
  },
];

async function initializePayPal() {
  try {
    // 1. Fetch Client configuration from backend
    const configRes = await fetch("/api/config");
    const config = await configRes.json();

    if (!config.isConfigured) {
      const warningEl = document.getElementById("credentials-warning");
      if (warningEl) warningEl.style.display = "block";
    }

    // 2. Dynamically load the PayPal JavaScript SDK with the configured Client ID
    const script = document.createElement("script");
    const clientIdParam = encodeURIComponent(config.clientId || "test");
    const currencyParam = encodeURIComponent(config.currency || "USD");

    script.src = `https://www.paypal.com/sdk/js?client-id=${clientIdParam}&currency=${currencyParam}&components=buttons&enable-funding=venmo,paylater`;
    script.async = true;

    script.onload = () => {
      renderPayPalButtons();
    };

    script.onerror = () => {
      showError("Failed to load PayPal JavaScript SDK. Please check your network connection and Client ID.");
    };

    document.head.appendChild(script);
  } catch (err) {
    showError("Could not connect to backend server: " + err.message);
  }
}

function renderPayPalButtons() {
  if (!window.paypal || !window.paypal.Buttons) {
    showError("PayPal SDK is not available.");
    return;
  }

  window.paypal
    .Buttons({
      style: {
        layout: "vertical",
        color: "gold",
        shape: "rect",
        label: "paypal",
      },

      /**
       * Step 1: Create Order on the Backend
       */
      async createOrder() {
        try {
          hideResults();
          const response = await fetch("/api/orders", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              cart: currentCart,
            }),
          });

          const orderData = await response.json();

          if (orderData.id) {
            console.log("Order created successfully:", orderData.id);
            return orderData.id;
          } else {
            const errorDetail = orderData?.details?.[0];
            const errorMessage = errorDetail
              ? `${errorDetail.issue}: ${errorDetail.description} (Debug ID: ${orderData.debug_id || "N/A"})`
              : orderData.error || JSON.stringify(orderData);

            throw new Error(errorMessage);
          }
        } catch (error) {
          console.error("Order creation error:", error);
          showError(`Could not initiate PayPal Checkout:<br>${error.message}`);
          throw error;
        }
      },

      /**
       * Step 2: On Buyer Approval, Capture Payment on the Backend
       */
      async onApprove(data, actions) {
        try {
          console.log("Buyer approved order:", data.orderID);

          const response = await fetch(`/api/orders/${data.orderID}/capture`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
          });

          const orderData = await response.json();
          const errorDetail = orderData?.details?.[0];

          // 1. Recoverable INSTRUMENT_DECLINED
          if (errorDetail?.issue === "INSTRUMENT_DECLINED") {
            console.warn("Instrument declined. Restarting flow...");
            return actions.restart();
          }

          // 2. Non-recoverable error
          if (errorDetail) {
            throw new Error(`${errorDetail.description} (${orderData.debug_id || "N/A"})`);
          }

          if (!orderData.purchase_units && !orderData.status) {
            throw new Error(orderData.error || JSON.stringify(orderData));
          }

          // 3. Successful capture
          const capture =
            orderData?.purchase_units?.[0]?.payments?.captures?.[0];
          const captureId = capture ? capture.id : "N/A";
          const captureStatus = capture ? capture.status : orderData.status;
          const payerEmail = orderData?.payer?.email_address || "N/A";

          showSuccess({
            status: captureStatus,
            orderId: orderData.id,
            captureId: captureId,
            payerEmail: payerEmail,
            raw: orderData,
          });

          console.log("Payment Capture result:", orderData);
        } catch (error) {
          console.error("Payment Capture error:", error);
          showError(`Transaction failed:<br>${error.message}`);
        }
      },

      /**
       * Handle cancellation
       */
      onCancel(data) {
        console.log("Buyer cancelled transaction:", data);
        showError("Transaction was cancelled by the buyer.");
      },

      /**
       * Handle SDK errors
       */
      onError(err) {
        console.error("PayPal Buttons error:", err);
        showError(`PayPal encountered an error:<br>${err.message || err}`);
      },
    })
    .render("#paypal-button-container");
}

function showSuccess({ status, orderId, captureId, payerEmail, raw }) {
  const card = document.getElementById("result-card");
  const title = document.getElementById("result-title");
  const content = document.getElementById("result-content");
  const jsonViewer = document.getElementById("json-viewer");

  card.className = "result-card success";
  title.innerHTML = `&#10004; Payment ${status}!`;
  content.innerHTML = `
    <strong>Order ID:</strong> ${orderId}<br>
    <strong>Capture ID:</strong> ${captureId}<br>
    <strong>Buyer Account:</strong> ${payerEmail}<br>
    <em>Money successfully authorized and captured in sandbox.</em>
  `;
  jsonViewer.textContent = JSON.stringify(raw, null, 2);
  card.style.display = "block";
}

function showError(message) {
  const card = document.getElementById("result-card");
  const title = document.getElementById("result-title");
  const content = document.getElementById("result-content");
  const jsonViewer = document.getElementById("json-viewer");

  card.className = "result-card error";
  title.innerHTML = `&#10060; Error`;
  content.innerHTML = message;
  jsonViewer.textContent = "";
  card.style.display = "block";
}

function hideResults() {
  const card = document.getElementById("result-card");
  if (card) card.style.display = "none";
}

// Start flow on load
window.addEventListener("DOMContentLoaded", initializePayPal);
