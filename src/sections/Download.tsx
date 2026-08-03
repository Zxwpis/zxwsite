import { useState } from 'react';
import {
  Download as DownloadIcon,
  Check,
  AlertTriangle,
  ExternalLink,
  Copy,
  CheckCircle2,
  MessageCircle,
  Gamepad2,
} from 'lucide-react';
import { useSectionReveal } from '../lib/anim';
import { HeadingFlip } from '../components/HeadingFlip';
import { DISCORD_INVITE_URL } from '../config/links';

const DOWNLOAD_URL =
  'https://drive.google.com/drive/folders/17UcwGUs-j4MrOIpu04aaLiXbC-eahWQM?usp=drive_link';

const requirements = [
  'Windows 10 or Windows 11',
  'Administrator privileges',
  'Internet connection for updates',
  '50MB disk space',
];

const steps = [
  {
    step: 1,
    title: 'Download',
    description: 'Get ZXWY V3 from our secure Google Drive folder.',
  },
  {
    step: 2,
    title: 'Extract',
    description: 'Extract the ZIP file to your desired location.',
  },
  {
    step: 3,
    title: 'Run',
    description: 'Right-click and run ZXWY_V3.exe as Administrator.',
  },
  {
    step: 4,
    title: 'Optimize',
    description: 'Select your desired tweaks and apply them.',
  },
];

const meta = [
  { label: 'Version', value: '3.0.0' },
  { label: 'Size', value: '~15 MB' },
  { label: 'Format', value: 'ZIP' },
  { label: 'Updated', value: 'July 2026' },
];

export function Download() {
  const ref = useSectionReveal();
  const [copied, setCopied] = useState(false);

  const handleCopyLink = () => {
    navigator.clipboard.writeText(DOWNLOAD_URL);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="download" ref={ref} className="section-shell bg-transparent">
      <div className="section-glow top-1/2 h-[420px] w-[720px] -translate-y-1/2 opacity-40" />

      <div className="section-container relative z-10">
        <div className="section-head" data-reveal>
          <span className="pill-outline">
            <DownloadIcon className="h-3.5 w-3.5" />
            Get started
          </span>
          <HeadingFlip
            className="section-title"
            front={[{ text: 'Download ' }, { text: 'ZXWY V3', lime: true }]}
            back={[{ text: 'One-time price, ' }, { text: 'no catch', lime: true }]}
          />
          <p className="section-lede">
            Get the latest version of ZXWY V3 and start optimizing your PC
            in minutes with our easy-to-use toolkit.
          </p>
        </div>

        <div className="grid items-stretch gap-5 lg:grid-cols-[1.35fr_1fr]">
          {/* Primary CTA slab */}
          <div
            data-reveal
            className="relative flex flex-col overflow-hidden rounded-[36px] bg-[#16191A] p-8 text-white sm:p-10 md:p-12"
          >
            <div className="relative z-10 flex flex-1 flex-col">
              <div className="mb-10 flex flex-wrap items-start justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className="grid h-14 w-14 place-items-center rounded-2xl bg-white/10">
                    <img
                      src="/logo.png"
                      alt="ZXWY V3 Logo"
                      className="h-9 w-9 object-contain"
                      width={36}
                      height={36}
                      loading="lazy"
                    />
                  </div>
                  <div>
                    <h3 className="display-quiet text-2xl text-white sm:text-3xl">
                      ZXWY V3
                    </h3>
                    <p className="mt-1 text-sm text-white/50">Latest release · One-time purchase</p>
                  </div>
                </div>
                <span className="pill-lime">v3.0</span>
              </div>

              <div className="mb-10 flex flex-wrap gap-2">
                {meta.map((item) => (
                  <span
                    key={item.label}
                    className="inline-flex items-center gap-2 rounded-full border border-white/15 px-3.5 py-1.5 font-mono text-[11px] font-bold uppercase tracking-[0.18em] text-white/70"
                  >
                    <span className="text-white/40">{item.label}</span>
                    {item.value}
                  </span>
                ))}
              </div>

              <div className="mt-auto space-y-3">
                <a
                  href={DOWNLOAD_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group inline-flex w-full items-center justify-center gap-2 rounded-full bg-[#36FE35] px-7 py-3.5 text-sm font-semibold text-[#16191A] transition-all duration-300 hover:-translate-y-0.5 hover:bg-white sm:w-auto sm:min-w-[280px]"
                >
                  <DownloadIcon className="h-4 w-4" />
                  Download from Google Drive
                  <ExternalLink className="h-4 w-4 opacity-60 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
                </a>

                <button
                  type="button"
                  onClick={handleCopyLink}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-full border border-white/20 px-7 py-3.5 text-sm font-semibold text-white/80 transition-all duration-300 hover:-translate-y-0.5 hover:border-white/50 hover:text-white sm:w-auto sm:min-w-[280px]"
                  aria-label={copied ? 'Download link copied' : 'Copy download link'}
                >
                  {copied ? (
                    <>
                      <CheckCircle2 className="h-4 w-4 text-[#36FE35]" />
                      Link copied!
                    </>
                  ) : (
                    <>
                      <Copy className="h-4 w-4" />
                      Copy download link
                    </>
                  )}
                </button>
              </div>

              <div className="mt-8 flex items-start gap-3 rounded-2xl border border-white/10 bg-white/[0.04] p-4">
                <div className="icon-chip shrink-0 bg-[#36FE35]/15 text-[#36FE35]">
                  <AlertTriangle className="h-5 w-5" />
                </div>
                <div className="text-sm leading-relaxed">
                  <p className="font-semibold text-white">Important</p>
                  <p className="mt-1 text-white/55">
                    Always create a system restore point before applying tweaks.
                    Use at your own risk.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Side tiles */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1">
            <div data-reveal className="card-paper">
              <div className="mb-5 flex items-center justify-between">
                <span className="index-tag">01 · Specs</span>
                <span className="icon-chip bg-[#36FE35]/15 text-[#16191a]">
                  <Check className="h-5 w-5" />
                </span>
              </div>
              <h3 className="mb-4 text-lg font-semibold tracking-tight text-[#16191a]">
                System requirements
              </h3>
              <ul className="space-y-3">
                {requirements.map((req) => (
                  <li key={req} className="flex items-start gap-3 text-sm text-[#16191a]/70">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#36FE35]" />
                    {req}
                  </li>
                ))}
              </ul>
            </div>

            <div data-reveal className="card-paper">
              <div className="mb-5 flex items-center justify-between">
                <span className="index-tag">02 · Install</span>
                <span className="pill-outline">4 steps</span>
              </div>
              <h3 className="mb-4 text-lg font-semibold tracking-tight text-[#16191a]">
                Installation steps
              </h3>
              <ol className="space-y-4">
                {steps.map((step) => (
                  <li key={step.step} className="flex items-start gap-3">
                    <span className="grid h-8 w-8 shrink-0 place-items-center rounded-full bg-[#16191a] font-mono text-xs font-bold text-[#36FE35]">
                      {step.step}
                    </span>
                    <div>
                      <p className="text-sm font-semibold text-[#16191a]">{step.title}</p>
                      <p className="mt-0.5 text-sm leading-relaxed text-[#16191a]/55">
                        {step.description}
                      </p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>

            <div data-reveal className="card-ink sm:col-span-2 lg:col-span-1">
              <p className="index-tag text-white/50">Need help?</p>
              <p className="mt-3 mb-5 max-w-xs text-sm leading-relaxed text-white/60">
                Join the community for install tips, troubleshooting and the latest builds.
              </p>
              <div className="flex flex-wrap gap-2.5">
                <a
                  href={DISCORD_INVITE_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-full bg-[#36FE35] px-5 py-2.5 text-sm font-semibold text-[#16191A] transition-all duration-300 hover:-translate-y-0.5 hover:bg-white"
                >
                  <Gamepad2 className="h-4 w-4" />
                  Discord
                </a>
                <a
                  href="https://t.me/ZXWYTWEAKING"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-full border border-white/20 px-5 py-2.5 text-sm font-semibold text-white/80 transition-all duration-300 hover:-translate-y-0.5 hover:border-white/50 hover:text-white"
                >
                  <MessageCircle className="h-4 w-4" />
                  Telegram
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
