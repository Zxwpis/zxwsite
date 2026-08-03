import { Zap, Shield, Cpu, Gauge, RefreshCw, Gamepad2, Layers, Settings } from 'lucide-react';
import { useSectionReveal } from '../lib/anim';
import { HeadingFlip } from '../components/HeadingFlip';

const features = [
  {
    icon: Zap,
    title: 'Performance Boost',
    description: 'Optimize Windows services, registry, and power settings for maximum gaming performance.',
    stat: '+40% FPS',
    tone: 'lime' as const,
    span: true,
  },
  {
    icon: Shield,
    title: 'Safe & Reversible',
    description: 'All tweaks include automatic restore points. One-click rollback anytime.',
    stat: '100% Safe',
    tone: 'ink' as const,
    span: false,
  },
  {
    icon: Cpu,
    title: 'System Debloat',
    description: 'Remove unnecessary Windows bloatware and background processes.',
    stat: '-15% Bloat',
    tone: 'paper' as const,
    span: false,
  },
  {
    icon: Gauge,
    title: 'Latency Reduction',
    description: 'Minimize input lag with advanced timer and interrupt optimizations.',
    stat: '-30% Latency',
    tone: 'ink' as const,
    span: false,
  },
  {
    icon: RefreshCw,
    title: 'Auto Updates',
    description: 'Get the latest optimizations automatically with our update system.',
    stat: 'Always Current',
    tone: 'paper' as const,
    span: false,
  },
  {
    icon: Gamepad2,
    title: 'Gaming Focused',
    description: 'Specifically designed for gamers who demand the best performance.',
    stat: 'Proven Results',
    tone: 'paper' as const,
    span: true,
  },
];

const v3Improvements = [
  {
    icon: Layers,
    title: 'New UI',
    description: 'Completely redesigned interface for easier navigation and control.',
  },
  {
    icon: Settings,
    title: 'More Options',
    description: '50+ new tweak options for fine-tuning your system.',
  },
];

const toneClass = {
  paper: 'card-paper',
  ink: 'card-ink',
  lime: 'card-lime',
} as const;

const chipClass = {
  paper: 'icon-chip bg-[#36FE35]/15 text-[#16191a]',
  ink: 'icon-chip bg-white/10 text-[#36FE35]',
  lime: 'icon-chip bg-[#16191a]/10 text-[#16191a]',
} as const;

const statClass = {
  paper: 'pill-outline',
  ink: 'pill-lime',
  lime: 'pill-ink',
} as const;

const titleClass = {
  paper: 'text-[#16191a]',
  ink: 'text-white',
  lime: 'text-[#16191a]',
} as const;

const descClass = {
  paper: 'text-[#16191a]/60',
  ink: 'text-white/60',
  lime: 'text-[#16191a]/70',
} as const;

export function Features() {
  const ref = useSectionReveal();

  return (
    <section id="features" ref={ref} className="section-shell">
      <div className="section-glow top-1/3 h-[420px] w-[720px] opacity-60" aria-hidden="true" />

      <div className="section-container relative z-10">
        <div className="section-head" data-reveal>
          <span className="pill-outline">
            <Zap className="h-3.5 w-3.5 text-[#36FE35]" />
            Powerful Features
          </span>
          <HeadingFlip
            className="section-title text-balance"
            front={[{ text: 'Everything you need for ' }, { text: 'maximum performance', lime: true }]}
            back={[{ text: 'No fluff, ' }, { text: 'just frames', lime: true }]}
          />
          <p className="section-lede">
            ZXWY V3 combines powerful optimization tools with an intuitive interface
            to give you complete control over your system&apos;s performance.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature) => (
            <article
              key={feature.title}
              data-reveal
              className={`group flex min-h-[240px] flex-col justify-between ${toneClass[feature.tone]} ${
                feature.span ? 'lg:col-span-2' : ''
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className={chipClass[feature.tone]}>
                  <feature.icon className="h-5 w-5" />
                </div>
                <span className={statClass[feature.tone]}>{feature.stat}</span>
              </div>

              <div className="mt-8 space-y-3">
                <h3 className={`text-xl font-semibold tracking-tight ${titleClass[feature.tone]}`}>
                  {feature.title}
                </h3>
                <p className={`max-w-md text-[15px] leading-relaxed ${descClass[feature.tone]}`}>
                  {feature.description}
                </p>
              </div>
            </article>
          ))}
        </div>

        {/* V3 improvements strip */}
        <div
          data-reveal
          className="card-ink mt-6 grid gap-8 p-8 md:grid-cols-[1.1fr_1fr] md:p-10"
        >
          <div className="space-y-5">
            <span className="pill-lime">
              <span className="h-1.5 w-1.5 rounded-full bg-[#16191a]" />
              What&apos;s new in V3
            </span>
            <h3 className="display-quiet text-[clamp(1.75rem,3vw,2.4rem)] text-white">
              Major upgrade from{' '}
              <span className="hl-lime">Version 2</span>
            </h3>
            <p className="max-w-md text-[15px] leading-relaxed text-white/55">
              We&apos;ve completely rebuilt ZXWY from the ground up with new features,
              better performance, and a more intuitive experience.
            </p>
            <div className="flex flex-wrap gap-3 pt-1">
              <div className="rounded-2xl border border-white/10 bg-white/5 px-5 py-3">
                <p className="metric text-[2rem] text-white">Up to 3x</p>
                <p className="metric-caption text-white">Faster tweak apply</p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 px-5 py-3">
                <p className="metric text-[2rem] text-white">50+</p>
                <p className="metric-caption text-white">New Tweaks</p>
              </div>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 md:grid-cols-1 lg:grid-cols-2">
            {v3Improvements.map((item) => (
              <div
                key={item.title}
                className="flex h-full flex-col gap-4 rounded-[22px] border border-white/10 bg-white/[0.04] p-5 transition-colors duration-300 hover:bg-white/[0.07]"
              >
                <div className="icon-chip bg-[#36FE35]/15 text-[#36FE35]">
                  <item.icon className="h-5 w-5" />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-white">{item.title}</h4>
                  <p className="mt-1.5 text-sm leading-relaxed text-white/55">
                    {item.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
