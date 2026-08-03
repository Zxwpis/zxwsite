import type { RefObject } from 'react';
import { motion } from 'framer-motion';
import { Check, Sparkles, Crown, Rocket } from 'lucide-react';
import { useCountUp, useSectionReveal } from '../lib/anim';
import { useShinyStyle } from '../components/ShinyText';
import { HeadingFlip } from '../components/HeadingFlip';
import { PayPalButton } from '../components/PayPalButton';
import { DISCORD_INVITE_URL } from '../config/links';

interface PricingPlan {
  id: string;
  name: string;
  priceValue: number;
  description: string;
  icon: typeof Sparkles;
  features: string[];
  highlighted?: boolean;
}

const plans: PricingPlan[] = [
  {
    id: 'standard',
    name: 'Standard',
    priceValue: 7,
    description: 'Perfect for casual gamers looking for a performance boost.',
    icon: Rocket,
    features: [
      'Windows optimization',
      'Custom power plan',
      'Basic service debloat',
      'Registry cleanup',
      'Email support',
    ],
  },
  {
    id: 'max',
    name: 'Max',
    priceValue: 12,
    description: 'Best for competitive players who want every millisecond of advantage.',
    icon: Crown,
    features: [
      'Everything in Standard',
      'Deep system debloating',
      'Advanced CPU & GPU tweaks',
      'RAM latency reduction',
      'Priority Discord support',
    ],
    highlighted: true,
  },
  {
    id: 'ultimate',
    name: 'Ultimate',
    priceValue: 20,
    description: 'The complete package with personal installation and optimization.',
    icon: Sparkles,
    features: [
      'Everything in Max',
      '1-on-1 personal setup',
      'BIOS optimization guide',
      'Network delay calibration',
      'Lifetime updates',
    ],
  },
];

function PlanPrice({ value, dark, shiny }: { value: number; dark?: boolean; shiny?: boolean }) {
  const ref = useCountUp(value, (n) => `$${Math.round(n)}`);
  // Hooks can't be called conditionally — always compute the shine style, only apply it
  // (via `style`) when this particular plan is actually the shiny one.
  const shinyStyle = useShinyStyle({ speed: 2.2, color: '#ffffff', shineColor: '#36FE35', spread: 100 });

  return (
    <motion.span
      ref={ref as RefObject<HTMLSpanElement>}
      className={`metric ${dark ? 'text-white' : 'text-[#16191a]'}`}
      style={shiny ? shinyStyle : undefined}
    />
  );
}

function PricingCard({ plan }: { plan: PricingPlan }) {
  const isHighlighted = Boolean(plan.highlighted);
  const cardTone = isHighlighted ? 'card-ink' : 'card-paper';

  return (
    <article
      data-reveal
      className={`group flex h-full flex-col ${cardTone} ${
        isHighlighted ? 'md:-mt-4 md:mb-0 md:min-h-[560px] lg:scale-[1.02]' : ''
      }`}
    >
      <div className="mb-8 flex items-start justify-between gap-3">
        <div
          className={`icon-chip ${
            isHighlighted
              ? 'bg-white/10 text-[#36FE35]'
              : 'bg-[#36FE35]/15 text-[#16191a]'
          }`}
        >
          <plan.icon className="h-5 w-5" />
        </div>
        {isHighlighted ? (
          <span className="pill-lime">Recommended</span>
        ) : (
          <span className="index-tag">{plan.id}</span>
        )}
      </div>

      <div
        className={`mb-8 space-y-3 border-b pb-8 ${
          isHighlighted ? 'border-white/10' : 'border-[#16191a]/10'
        }`}
      >
        <h3
          className={`text-2xl font-semibold tracking-tight ${
            isHighlighted ? 'text-white' : 'text-[#16191a]'
          }`}
        >
          {plan.name}
        </h3>
        <div className="flex items-end gap-2">
          <PlanPrice value={plan.priceValue} dark={isHighlighted} shiny={isHighlighted} />
          <span
            className={`mb-1 text-[11px] font-bold uppercase tracking-[0.18em] ${
              isHighlighted ? 'text-white/45' : 'text-[#16191a]/45'
            }`}
          >
            / one-time
          </span>
        </div>
        <p
          className={`text-sm leading-relaxed ${
            isHighlighted ? 'text-white/55' : 'text-[#16191a]/60'
          }`}
        >
          {plan.description}
        </p>
      </div>

      <ul className="mb-8 flex-1 space-y-3.5">
        {plan.features.map((feature) => (
          <li key={feature} className="flex items-start gap-3">
            <span
              className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full ${
                isHighlighted
                  ? 'bg-[#36FE35]/15 text-[#36FE35]'
                  : 'bg-[#36FE35]/20 text-[#16191a]'
              }`}
            >
              <Check className="h-3 w-3" strokeWidth={2.5} />
            </span>
            <span
              className={`text-sm font-medium leading-snug ${
                isHighlighted ? 'text-white/85' : 'text-[#16191a]/80'
              }`}
            >
              {feature}
            </span>
          </li>
        ))}
      </ul>

      <div className="mt-auto">
        <PayPalButton amount={plan.priceValue} description={`ZXWY V3 — ${plan.name}`} dark={isHighlighted} />
      </div>
    </article>
  );
}

export function Pricing() {
  const ref = useSectionReveal();

  return (
    <section id="pricing" ref={ref} className="section-shell">
      <div className="section-glow top-1/4 h-[380px] w-[640px] opacity-50" aria-hidden="true" />

      <div className="section-container relative z-10">
        <div className="section-head" data-reveal>
          <span className="pill-outline">
            <Sparkles className="h-3.5 w-3.5 text-[#36FE35]" />
            Plans
          </span>
          <HeadingFlip
            className="section-title text-balance"
            front={[{ text: 'Choose your ' }, { text: 'optimization level', lime: true }]}
            back={[{ text: 'One price, ' }, { text: 'no subscriptions', lime: true }]}
          />
          <p className="section-lede">
            One-time purchase. Lifetime value. Upgrade your gaming performance today.
          </p>
        </div>

        <div className="grid w-full items-stretch gap-4 md:grid-cols-3 md:gap-5">
          {plans.map((plan) => (
            <PricingCard key={plan.id} plan={plan} />
          ))}
        </div>

        <div data-reveal className="mt-12 flex justify-center">
          <p className="card-paper inline-flex max-w-xl flex-wrap items-center justify-center gap-x-2 gap-y-2 px-6 py-4 text-center text-sm text-[#16191a]/65">
            Have questions about which plan to choose?
            <a
              href={DISCORD_INVITE_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-full bg-[#36FE35] px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-[#16191a] transition-all duration-300 hover:-translate-y-0.5"
            >
              Contact us on Discord
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}
