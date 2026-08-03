import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutGrid,
  LayoutDashboard,
  Sliders,
  Bookmark,
  Shield,
  Settings as SettingsIcon,
  Minus,
  Square,
  X,
  Wifi,
  Lock,
  Cpu,
  Activity,
  MemoryStick,
  Sparkles,
} from 'lucide-react';
import { useSectionReveal } from '../lib/anim';
import { HeadingFlip } from '../components/HeadingFlip';
import { DEMO_TWEAKS, TIERS, TIER_LABELS, type DemoTier, isDemoTweakAllowed } from '../data/demoTweaks';

type DemoPage = 'dashboard' | 'tweaks' | 'presets' | 'restore' | 'settings';

interface NavItem {
  key: DemoPage;
  label: string;
  icon: typeof LayoutDashboard;
  interactive: boolean;
}

const NAV: NavItem[] = [
  { key: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, interactive: true },
  { key: 'tweaks', label: 'Tweaks', icon: Sliders, interactive: true },
  { key: 'presets', label: 'Presets', icon: Bookmark, interactive: false },
  { key: 'restore', label: 'Restore', icon: Shield, interactive: false },
  { key: 'settings', label: 'Settings', icon: SettingsIcon, interactive: false },
];

function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function randomWalk(value: number, min: number, max: number, step: number) {
  return clamp(value + (Math.random() - 0.5) * step, min, max);
}

export function Showcase() {
  const ref = useSectionReveal();
  const [page, setPage] = useState<DemoPage>('dashboard');
  const [tier, setTier] = useState<DemoTier>('Standard');
  const [stats, setStats] = useState({ cpu: 18, gpu: 34, ram: 42 });
  const [tweakState, setTweakState] = useState<Record<string, boolean>>({});

  const unlockedCount = DEMO_TWEAKS.filter((t) => isDemoTweakAllowed(t, tier)).length;

  // Fake live telemetry — random-walked so the numbers feel alive, not real system data.
  useEffect(() => {
    const id = setInterval(() => {
      setStats((s) => ({
        cpu: randomWalk(s.cpu, 8, 55, 10),
        gpu: randomWalk(s.gpu, 15, 78, 14),
        ram: randomWalk(s.ram, 30, 68, 6),
      }));
    }, 1400);
    return () => clearInterval(id);
  }, []);

  const toggleTweak = (code: string) => {
    setTweakState((s) => ({ ...s, [code]: !s[code] }));
  };

  return (
    <section id="showcase" ref={ref} className="section-shell bg-transparent">
      <div className="section-glow top-1/3 h-[420px] w-[720px] opacity-40" aria-hidden="true" />

      <div className="section-container relative z-10">
        <div className="section-head" data-reveal>
          <span className="pill-outline">
            <LayoutGrid className="h-3.5 w-3.5 text-[#36FE35]" />
            Inside the app
          </span>
          <HeadingFlip
            className="section-title text-balance"
            front={[{ text: 'Try it before you ' }, { text: 'install it', lime: true }]}
            back={[{ text: 'A real, ' }, { text: 'limited demo', lime: true }]}
          />
          <p className="section-lede">
            This is the actual ZXWY V3 window, running in your browser. Switch the demo tier below and click
            through Dashboard / Tweaks — everything else stays locked, just like an unlicensed copy.
          </p>
        </div>

        {/* App window replica */}
        <div data-reveal className="relative mx-auto mt-10 max-w-4xl">
          <div className="overflow-hidden rounded-[16px] border border-[#16191a]/10 bg-[#0c0f0d] shadow-soft">
            {/* Title bar — mirrors the real app's window chrome */}
            <div className="flex h-9 select-none items-center border-b border-white/8 bg-[#0c0f0d]/95">
              <div className="flex min-w-0 items-center gap-2 px-3">
                <div className="h-2 w-2 shrink-0 rounded-full bg-[#36FE35] shadow-[0_0_8px_rgba(54,254,53,0.8)]" />
                <span className="truncate text-[11px] font-bold tracking-[0.18em] text-white">
                  ZXWY <span className="text-[#36FE35]">TWEAKS</span>
                </span>
              </div>
              <div className="ml-3 hidden items-center gap-1.5 text-[10px] sm:flex">
                <Wifi className="h-3 w-3 text-[#36FE35]" />
                <span className="uppercase tracking-wider text-white/50">
                  {TIER_LABELS[tier]}
                </span>
              </div>
              <div className="flex-1" />
              <div className="flex shrink-0">
                <span className="inline-flex h-9 w-8 items-center justify-center text-white/25 sm:w-11">
                  <Minus className="h-3.5 w-3.5" />
                </span>
                <span className="inline-flex h-9 w-8 items-center justify-center text-white/25 sm:w-11">
                  <Square className="h-3 w-3" />
                </span>
                <span className="inline-flex h-9 w-8 items-center justify-center text-white/25 sm:w-11">
                  <X className="h-3.5 w-3.5" />
                </span>
              </div>
            </div>

            <div className="flex h-[440px] sm:h-[480px] md:h-[520px]">
              {/* Sidebar — mirrors the real app's navigation. Icon-only + narrower on phones so it
                  doesn't eat most of the available width; labels return from `sm:` up. */}
              <aside className="flex w-14 shrink-0 flex-col border-r border-white/8 bg-white/[0.015] sm:w-48">
                <nav className="flex flex-1 flex-col gap-0.5 p-2">
                  {NAV.map((item) => {
                    const active = page === item.key;
                    if (!item.interactive) {
                      return (
                        <span
                          key={item.key}
                          title="Available in the full app"
                          aria-disabled="true"
                          className="flex h-9 cursor-not-allowed items-center justify-center gap-2.5 rounded-md px-0 text-xs font-medium text-white/20 sm:justify-start sm:px-3"
                        >
                          <item.icon className="h-4 w-4 shrink-0" />
                          <span className="hidden flex-1 sm:inline">{item.label}</span>
                          <Lock className="hidden h-3 w-3 sm:inline" />
                        </span>
                      );
                    }
                    return (
                      <button
                        key={item.key}
                        onClick={() => setPage(item.key)}
                        title={item.label}
                        className={`relative flex h-9 items-center justify-center gap-2.5 rounded-md px-0 text-xs font-medium transition-colors sm:justify-start sm:px-3 ${
                          active ? 'bg-[#36FE35]/10 text-[#36FE35]' : 'text-white/50 hover:bg-white/5 hover:text-white/80'
                        }`}
                      >
                        {active && (
                          <motion.div
                            layoutId="demo-sidebar-active"
                            className="absolute bottom-1.5 left-0 top-1.5 w-0.5 rounded-r-full bg-[#36FE35] shadow-[0_0_8px_rgba(54,254,53,0.6)]"
                          />
                        )}
                        <item.icon className="h-4 w-4 shrink-0" />
                        <span className="hidden sm:inline">{item.label}</span>
                      </button>
                    );
                  })}
                </nav>

                {/* Demo tier switch — replaces the real license key panel */}
                <div className="space-y-2 border-t border-white/8 p-1.5 sm:p-3">
                  <div className="hidden text-[9px] uppercase tracking-[0.2em] text-white/25 sm:block">Demo tier</div>
                  <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
                    {TIERS.map((t) => (
                      <button
                        key={t}
                        onClick={() => setTier(t)}
                        title={TIER_LABELS[t]}
                        className={`rounded px-1 py-1 text-[9px] font-bold uppercase tracking-wide transition-colors sm:px-1.5 sm:text-[10px] ${
                          tier === t ? 'bg-[#36FE35]/15 text-[#36FE35]' : 'bg-white/5 text-white/35 hover:text-white/60'
                        }`}
                      >
                        <span className="block truncate">{TIER_LABELS[t]}</span>
                      </button>
                    ))}
                  </div>
                  <div className="hidden text-center font-mono text-[9px] text-white/20 sm:block">v3.0.0 · demo</div>
                </div>
              </aside>

              {/* Main content */}
              <div className="relative flex-1 overflow-y-auto p-4 sm:p-6">
                <AnimatePresence mode="wait">
                  <motion.div
                    key={page}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.3, ease: 'easeOut' }}
                  >
                    {page === 'dashboard' && (
                      <DashboardDemo stats={stats} unlockedCount={unlockedCount} onOpenTweaks={() => setPage('tweaks')} />
                    )}
                    {page === 'tweaks' && (
                      <TweaksDemo tier={tier} tweakState={tweakState} onToggle={toggleTweak} />
                    )}
                  </motion.div>
                </AnimatePresence>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function StatCard({
  label,
  value,
  unit,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  unit: string;
  icon: typeof Cpu;
  color: string;
}) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-white/8 bg-white/[0.03] p-4">
      <div
        className="pointer-events-none absolute inset-0 opacity-25"
        style={{ background: `radial-gradient(circle at 100% 100%, ${color}25 0%, transparent 60%)` }}
      />
      <div className="flex items-center gap-2 text-white/40">
        <Icon className="h-4 w-4" />
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em]">{label}</span>
      </div>
      <div className="mt-3 flex items-baseline gap-1">
        <span className="text-3xl font-bold tabular-nums tracking-tight" style={{ color }}>
          {value.toFixed(0)}
        </span>
        <span className="text-sm text-white/30">{unit}</span>
      </div>
      <div className="mt-4 h-1 overflow-hidden rounded-full bg-white/10">
        <motion.div
          className="h-full rounded-full"
          style={{ background: color, boxShadow: `0 0 12px ${color}90` }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        />
      </div>
    </div>
  );
}

function ActionCard({
  icon: Icon,
  title,
  subtitle,
  locked,
  onClick,
}: {
  icon: typeof Sparkles;
  title: string;
  subtitle: string;
  locked?: boolean;
  onClick?: () => void;
}) {
  if (locked) {
    return (
      <span
        title="Available in the full app"
        className="flex cursor-not-allowed flex-col items-start rounded-xl border border-white/8 bg-white/[0.02] p-4 text-left opacity-40"
      >
        <Icon className="h-5 w-5 text-white/30" />
        <div className="mt-2 text-sm font-bold text-white/50">{title}</div>
        <div className="mt-0.5 text-xs text-white/25">{subtitle}</div>
      </span>
    );
  }
  return (
    <button
      onClick={onClick}
      className="group flex flex-col items-start rounded-xl border border-white/8 bg-white/[0.03] p-4 text-left transition-colors hover:border-[#36FE35]/30 hover:bg-white/[0.05]"
    >
      <Icon className="h-5 w-5 text-white/40 transition-colors group-hover:text-[#36FE35]" />
      <div className="mt-2 text-sm font-bold text-white">{title}</div>
      <div className="mt-0.5 text-xs text-white/35">{subtitle}</div>
    </button>
  );
}

function DashboardDemo({
  stats,
  unlockedCount,
  onOpenTweaks,
}: {
  stats: { cpu: number; gpu: number; ram: number };
  unlockedCount: number;
  onOpenTweaks: () => void;
}) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-[0.2em] text-white/30">Live Telemetry</div>
      <h3 className="mt-0.5 text-xl font-bold tracking-tight text-white">System Dashboard</h3>

      <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <StatCard label="CPU Load" value={stats.cpu} unit="%" icon={Cpu} color="#36FE35" />
        <StatCard label="GPU Load" value={stats.gpu} unit="%" icon={Activity} color="#54ffa9" />
        <StatCard label="RAM Usage" value={stats.ram} unit="%" icon={MemoryStick} color="#7dd3ff" />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <ActionCard icon={Sparkles} title="Apply tweaks" subtitle={`${unlockedCount} unlocked for your tier`} onClick={onOpenTweaks} />
        <ActionCard icon={Bookmark} title="Saved presets" subtitle="No presets yet" locked />
        <ActionCard icon={Shield} title="Restore points" subtitle="Backup before applying" locked />
      </div>

      <p className="mt-6 text-xs leading-relaxed text-white/25">
        Values above are simulated for this browser preview — the real app reads live system telemetry, restore
        points, presets, and ping monitoring across regional servers.
      </p>
    </div>
  );
}

function DemoToggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <button
      onClick={onChange}
      className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${
        on ? 'bg-[#36FE35] shadow-[0_0_12px_rgba(54,254,53,0.5)]' : 'bg-white/15'
      }`}
    >
      <motion.div
        className="absolute top-0.5 h-4 w-4 rounded-full bg-[#0c0f0d]"
        animate={{ x: on ? 18 : 2 }}
        transition={{ type: 'spring', stiffness: 700, damping: 30 }}
      />
    </button>
  );
}

function TweaksDemo({
  tier,
  tweakState,
  onToggle,
}: {
  tier: DemoTier;
  tweakState: Record<string, boolean>;
  onToggle: (code: string) => void;
}) {
  return (
    <div>
      <div className="flex items-baseline gap-2">
        <h3 className="text-xl font-bold tracking-tight text-white">Tweaks</h3>
        <span className="text-xs text-white/30">
          {Object.values(tweakState).filter(Boolean).length} toggled · preview only, nothing is applied
        </span>
      </div>

      <div className="mt-5 columns-1 gap-2.5 sm:columns-2 [column-fill:balance]">
        {DEMO_TWEAKS.map((t) => {
          const allowed = isDemoTweakAllowed(t, tier);
          const on = !!tweakState[t.code] && allowed;
          return (
            <div key={t.code} className="mb-2.5 break-inside-avoid">
              <div
                className={`flex items-start gap-3 rounded-xl border p-3.5 transition-colors ${
                  on ? 'border-[#36FE35]/30 bg-[#36FE35]/[0.06]' : 'border-white/8 bg-white/[0.03]'
                } ${!allowed ? 'opacity-45' : ''}`}
              >
                <div
                  className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${
                    on ? 'bg-[#36FE35]/15 text-[#36FE35]' : 'bg-white/5 text-white/40'
                  }`}
                >
                  <t.icon className="h-4.5 w-4.5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-bold text-white">{t.name}</span>
                    <span className="rounded-full border border-white/10 bg-white/5 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-white/40">
                      {t.tier}
                    </span>
                  </div>
                  <div className="mt-0.5 text-xs text-white/30">{t.description}</div>
                </div>
                {!allowed ? (
                  <Lock className="h-4 w-4 shrink-0 text-white/25" />
                ) : (
                  <DemoToggle on={on} onChange={() => onToggle(t.code)} />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
