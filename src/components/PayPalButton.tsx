import { useEffect, useRef, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { loadPayPalSdk, type PayPalButtonsInstance } from '../lib/paypal';

interface PayPalButtonProps {
  /** Price in USD — the PayPal order is created from this value, so it always matches the site. */
  amount: number;
  /** Shown on the PayPal order/receipt, e.g. the plan name. */
  description: string;
  dark?: boolean;
}

export function PayPalButton({ amount, description, dark }: PayPalButtonProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<'loading' | 'ready' | 'error'>('loading');

  useEffect(() => {
    let cancelled = false;
    let buttons: PayPalButtonsInstance | undefined;

    loadPayPalSdk()
      .then((paypal) => {
        if (cancelled || !containerRef.current) return;
        containerRef.current.innerHTML = '';

        buttons = paypal.Buttons({
          style: {
            layout: 'horizontal',
            color: dark ? 'gold' : 'black',
            shape: 'pill',
            label: 'pay',
            tagline: false,
            height: 45,
          },
          createOrder: (_: unknown, actions: any) =>
            actions.order.create({
              intent: 'CAPTURE',
              purchase_units: [
                {
                  description,
                  amount: { currency_code: 'USD', value: amount.toFixed(2) },
                },
              ],
            }),
          onApprove: async (_: unknown, actions: any) => {
            await actions.order.capture();
            toast.success('Payment successful! Check your email for delivery instructions.');
          },
          onError: () => {
            toast.error('Payment failed. Please try again or reach out on Discord.');
          },
        });

        buttons
          .render(containerRef.current)
          .then(() => {
            if (!cancelled) setStatus('ready');
          })
          .catch(() => {
            if (!cancelled) setStatus('error');
          });
      })
      .catch(() => {
        if (!cancelled) setStatus('error');
      });

    return () => {
      cancelled = true;
      buttons?.close?.();
    };
  }, [amount, description, dark]);

  return (
    <div className="w-full">
      <div ref={containerRef} className={status === 'ready' ? '' : 'hidden'} />
      {status === 'loading' && (
        <div
          className={`inline-flex w-full items-center justify-center gap-2 rounded-full px-7 py-3.5 text-sm font-semibold ${
            dark ? 'bg-[#36FE35]/50 text-[#16191A]' : 'bg-[#16191a]/60 text-white'
          }`}
        >
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading checkout...
        </div>
      )}
      {status === 'error' && (
        <p className="rounded-full border border-[#16191a]/15 px-7 py-3.5 text-center text-sm font-semibold text-[#16191a]/60">
          Checkout unavailable — try again later.
        </p>
      )}
    </div>
  );
}
