// Loads the official PayPal JS SDK once and reuses it for every checkout button on the page.
// The order (and therefore the price shown/charged) is created dynamically from the plan data
// in `Pricing.tsx`, so there is nothing to keep in sync manually on paypal.com anymore —
// change the price in code and every button picks it up automatically.

declare global {
  interface Window {
    paypal?: PayPalNamespace;
  }
}

export interface PayPalButtonsInstance {
  render: (container: HTMLElement) => Promise<void>;
  close?: () => void;
}

interface PayPalNamespace {
  Buttons: (options: Record<string, unknown>) => PayPalButtonsInstance;
}

// Falls back to PayPal's public sandbox client id ("sb") so the button still renders and can be
// tested end-to-end during development. Set VITE_PAYPAL_CLIENT_ID in a `.env` file to your live
// (or sandbox) client id from https://developer.paypal.com/dashboard/applications before going live.
const PAYPAL_CLIENT_ID = import.meta.env.VITE_PAYPAL_CLIENT_ID || 'sb';

let sdkPromise: Promise<PayPalNamespace> | null = null;

export function loadPayPalSdk(currency = 'USD'): Promise<PayPalNamespace> {
  if (window.paypal) {
    return Promise.resolve(window.paypal);
  }

  if (!sdkPromise) {
    sdkPromise = new Promise<PayPalNamespace>((resolve, reject) => {
      const existing = document.querySelector<HTMLScriptElement>('script[data-paypal-sdk]');
      if (existing && window.paypal) {
        resolve(window.paypal);
        return;
      }

      const script = document.createElement('script');
      script.src = `https://www.paypal.com/sdk/js?client-id=${PAYPAL_CLIENT_ID}&currency=${currency}&intent=capture&components=buttons`;
      script.async = true;
      script.dataset.paypalSdk = 'true';
      script.onload = () => {
        if (window.paypal) {
          resolve(window.paypal);
        } else {
          reject(new Error('PayPal SDK loaded but window.paypal is unavailable'));
        }
      };
      script.onerror = () => reject(new Error('Failed to load the PayPal SDK'));
      document.body.appendChild(script);
    });
  }

  return sdkPromise;
}
