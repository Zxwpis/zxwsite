import { useRef } from 'react';
import { motion } from 'framer-motion';
import { ArrowUp, ArrowUpRight } from 'lucide-react';
import { FaDiscord, FaTelegramPlane } from 'react-icons/fa';
import { DISCORD_INVITE_URL } from '../config/links';
import FaultyTerminal from '../components/FaultyTerminal';

const footerLinks = {
  product: [
    { label: 'Download', href: '#download' },
    { label: 'Features', href: '#features' },
    { label: 'Changelog', href: '#changelog' },
    { label: 'Pricing', href: '#pricing' },
  ],
  support: [
    { label: 'FAQ', href: '#faq' },
    { label: 'Contact', href: '#contact' },
    { label: 'Discord', href: DISCORD_INVITE_URL },
    { label: 'Telegram', href: 'https://t.me/ZXWYTWEAKING' },
  ],
  legal: [
    { label: 'Privacy Policy', href: '#' },
    { label: 'Terms of Service', href: '#' },
    { label: 'Disclaimer', href: '#' },
  ],
};

const socials = [
  { icon: FaTelegramPlane, href: 'https://t.me/ZXWYTWEAKING', label: 'Telegram' },
  { icon: FaDiscord, href: DISCORD_INVITE_URL, label: 'Discord' },
];


export function Footer() {
  const wordmarkRef = useRef<HTMLDivElement>(null);

  const scrollToSection = (href: string) => {
    if (href.startsWith('#')) {
      document.querySelector(href)?.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleWordmarkMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const el = wordmarkRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    el.style.setProperty('--x', `${e.clientX - rect.left}px`);
    el.style.setProperty('--y', `${e.clientY - rect.top}px`);
  };

  const renderColumn = (
    index: string,
    title: string,
    links: { label: string; href: string }[]
  ) => (
    <div>
      <p className="index-tag mb-5 text-[#36FE35]/70">
        {index} · {title}
      </p>
      <ul className="space-y-3.5">
        {links.map((link) => (
          <li key={link.label}>
            <a
              href={link.href}
              onClick={(e) => {
                if (link.href.startsWith('#')) {
                  e.preventDefault();
                  scrollToSection(link.href);
                }
              }}
              target={link.href.startsWith('http') ? '_blank' : undefined}
              rel={link.href.startsWith('http') ? 'noopener noreferrer' : undefined}
              className="group inline-flex items-center gap-1.5 text-[15px] text-white/65 transition-colors duration-300 hover:text-white"
            >
              {link.label}
              <ArrowUpRight className="h-3.5 w-3.5 text-[#36FE35] opacity-0 -translate-x-1 transition-all duration-300 group-hover:opacity-100 group-hover:translate-x-0" />
            </a>
          </li>
        ))}
      </ul>
    </div>
  );

  return (
    <footer className="relative px-4 pb-4 pt-24 sm:px-6">
      <div className="relative mx-auto max-w-[1440px]">
        {/* ── Block 1: full-bleed lime hero — the loud, unmistakable first read ── */}
        <div className="relative overflow-hidden rounded-[36px] bg-[#36FE35] px-7 pb-28 pt-16 text-[#16191A] sm:px-12 sm:pb-36 sm:pt-20">
          {/* Same digital-glitch background as the Hero, blended over the lime field instead of
              inverted to white — "lighten" blend mode keeps the black clear color hidden (lime
              stays lime wherever the src is darker) while the brightest specks reach true white,
              since "screen" can't beat lime's already-high green channel and looked tinted green. */}
          <div className="absolute inset-0 mix-blend-lighten" aria-hidden="true">
            <FaultyTerminal
              scale={3.2}
              gridMul={[2, 1]}
              digitSize={1}
              timeScale={0.5}
              scanlineIntensity={0.4}
              glitchAmount={1}
              flickerAmount={0.8}
              noiseAmp={1}
              chromaticAberration={0}
              dither={0}
              curvature={0}
              tint="#FFFFFF"
              mouseReact
              mouseStrength={0.3}
              pageLoadAnimation
              brightness={1}
            />
          </div>

          <div className="relative mx-auto max-w-3xl text-center">
            <span className="pill-ink mx-auto">
              <span className="h-1.5 w-1.5 rounded-full bg-[#36FE35]" />
              ready when you are
            </span>

            <h2 className="display-dot mt-8 text-[clamp(2.75rem,8.5vw,7rem)] leading-[0.94] tracking-[0.01em]">
              Stop losing
              <br />
              frames.
            </h2>

            <p className="mx-auto mt-7 max-w-md text-[15px] leading-relaxed text-[#16191A]/70">
              One download, zero bloat, every tweak reversible. Join the players who
              already squeezed every frame out of their machines.
            </p>

            <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
              <button
                onClick={() => scrollToSection('#download')}
                className="group inline-flex items-center gap-2 rounded-full bg-[#16191A] px-7 py-3.5 text-sm font-semibold text-white transition-all duration-300 hover:-translate-y-0.5 hover:bg-black"
              >
                Download ZXWY V3
                <ArrowUpRight className="h-4 w-4 text-[#36FE35] transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
              </button>
              <button
                onClick={() => scrollToSection('#contact')}
                className="inner-blur inline-flex items-center gap-2 rounded-full border border-[#16191A]/25 bg-white/10 px-7 py-3.5 text-sm font-semibold text-[#16191A]/80 backdrop-blur-md transition-all duration-300 hover:-translate-y-0.5 hover:border-[#16191A]/60 hover:bg-white/20 hover:text-[#16191A]"
              >
                Talk to us
              </button>
            </div>
          </div>
        </div>

        {/* ── Block 2: dark card floating up into the lime block above ── */}
        <div className="relative z-10 -mt-16 rounded-[30px] bg-[#16191A] px-7 pt-12 text-white shadow-[0_30px_80px_-30px_rgba(0,0,0,0.55)] sm:-mt-20 sm:px-12">
          {/* Brand + link columns */}
          <div className="grid gap-10 py-12 md:grid-cols-2 lg:grid-cols-[1.3fr_1fr_1fr_1fr]">
            <div className="space-y-5">
              <motion.a
                href="#hero"
                onClick={(e) => { e.preventDefault(); scrollToSection('#hero'); }}
                className="inline-flex items-center gap-3"
                whileHover={{ scale: 1.02 }}
              >
                <div className="grid h-11 w-11 place-items-center rounded-2xl bg-white/10">
                  <img
                    src="/White.png"
                    alt="ZXWY V3 Logo"
                    className="h-7 w-7 object-contain"
                    loading="lazy"
                    width={28}
                    height={28}
                  />
                </div>
                <span className="text-[17px] font-semibold tracking-tight text-white">
                  ZXWY <span className="text-[#36FE35]">V3</span>
                </span>
              </motion.a>
              <p className="max-w-xs text-sm leading-relaxed text-white/50">
                The PC optimization toolkit for people who care about the last frame,
                the last millisecond and nothing else.
              </p>
              <div className="flex gap-2.5">
                {socials.map((social) => (
                  <motion.a
                    key={social.label}
                    href={social.href}
                    target={social.href.startsWith('http') ? '_blank' : undefined}
                    rel={social.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                    className="grid h-10 w-10 place-items-center rounded-full border border-white/15 text-white/70 transition-all duration-300 hover:-translate-y-1 hover:border-[#36FE35] hover:bg-[#36FE35] hover:text-[#16191A]"
                    aria-label={social.label}
                    whileTap={{ scale: 0.92 }}
                  >
                    <social.icon className="h-4 w-4" />
                  </motion.a>
                ))}
              </div>
            </div>

            {renderColumn('01', 'Product', footerLinks.product)}
            {renderColumn('02', 'Support', footerLinks.support)}
            {renderColumn('03', 'Legal', footerLinks.legal)}
          </div>

          {/* Oversized interactive wordmark — hover to sweep a lime spotlight across it */}
          <div
            ref={wordmarkRef}
            onMouseMove={handleWordmarkMove}
            className="group/wordmark relative -mx-7 select-none overflow-hidden px-7 sm:-mx-12 sm:px-12"
          >
            <p
              aria-hidden="true"
              className="display-dot -mb-[0.14em] whitespace-nowrap text-[clamp(3rem,15vw,11rem)] leading-[0.9] tracking-[0.02em] text-white/[0.08]"
            >
              ZXWY V3
            </p>
            <p
              aria-hidden="true"
              className="spotlight-reveal pointer-events-none absolute inset-0 -mb-[0.14em] whitespace-nowrap px-7 text-[clamp(3rem,15vw,11rem)] leading-[0.9] tracking-[0.02em] text-[#36FE35] opacity-0 transition-opacity duration-300 group-hover/wordmark:opacity-100 sm:px-12"
              style={{ fontFamily: "'Dotective', 'Fraunces', Georgia, serif" }}
            >
              ZXWY V3
            </p>
          </div>

          {/* Bottom bar */}
          <div className="relative -mx-7 border-t border-white/10 px-7 py-6 sm:-mx-12 sm:px-12">
            <div className="flex flex-col items-center justify-between gap-3 text-xs text-white/40 sm:flex-row">
              <p>© 2026 ZXWY V3. All rights reserved.</p>
              <motion.button
                onClick={() => scrollToSection('#hero')}
                whileHover={{ y: -2 }}
                whileTap={{ scale: 0.94 }}
                aria-label="Back to top"
                className="grid h-9 w-9 place-items-center rounded-full border border-white/15 text-white/60 transition-colors duration-300 hover:border-[#36FE35] hover:text-[#36FE35]"
              >
                <ArrowUp className="h-4 w-4" />
              </motion.button>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
