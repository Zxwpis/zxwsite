import { useEffect, useRef } from 'react';
import { ArrowLeft, ArrowUpRight } from 'lucide-react';
import gsap from 'gsap';
import { animate, stagger } from 'motion';
import { SilkShader } from '../components/SilkShader';

const quickLinks = [
  { label: 'Home', href: '/' },
  { label: 'Download', href: '/#download' },
  { label: 'Pricing', href: '/#pricing' },
  { label: 'Contact', href: '/#contact' },
];

export function NotFound() {
  const codeRef = useRef<HTMLParagraphElement>(null);
  const copyRef = useRef<HTMLDivElement>(null);
  const linksRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (reduced) {
      gsap.set([codeRef.current, copyRef.current, linksRef.current], { opacity: 1, y: 0 });
      return;
    }

    const tl = gsap.timeline();

    tl.fromTo(
      codeRef.current,
      { opacity: 0, scale: 0.94, filter: 'blur(14px)' },
      { opacity: 1, scale: 1, filter: 'blur(0px)', duration: 1.1, ease: 'power3.out' }
    ).fromTo(
      copyRef.current,
      { opacity: 0, y: 18 },
      { opacity: 1, y: 0, duration: 0.6, ease: 'power3.out' },
      '-=0.55'
    );

    // Motion One handles the quick links so they trail in after the headline
    const items = linksRef.current?.querySelectorAll('a');
    if (items?.length) {
      animate(
        items,
        { opacity: [0, 1], transform: ['translateY(12px)', 'translateY(0px)'] },
        { duration: 0.45, delay: stagger(0.07, { startDelay: 0.75 }), ease: [0.16, 1, 0.3, 1] }
      );
    }

    // The dotted glyphs breathe very slowly so the page never feels dead
    const float = gsap.to(codeRef.current, {
      y: -10,
      duration: 4,
      ease: 'sine.inOut',
      yoyo: true,
      repeat: -1,
      delay: 1,
    });

    return () => {
      tl.kill();
      float.kill();
    };
  }, []);

  return (
    <main className="relative flex min-h-screen flex-col overflow-hidden bg-white text-[#16191A]">
      {/* Same silk field as the hero, so 404 still feels like our product */}
      <div className="pointer-events-none absolute inset-0 z-0 mask-fade-y">
        <SilkShader variant="light" speed={0.7} className="opacity-70" />
      </div>

      <div className="section-container relative z-10 flex min-h-screen flex-col py-10">
        <a
          href="/"
          className="link-arrow w-fit text-sm font-semibold text-[#16191a]/60 hover:text-[#16191a]"
        >
          <ArrowLeft className="h-4 w-4 transition-transform duration-300 group-hover:-translate-x-0.5" />
          ZXWY <span className="text-[#36FE35]">V3</span>
        </a>

        {/* Oversized dotted code — the whole point of the page */}
        <div className="flex flex-1 items-center justify-center py-10">
          <p
            ref={codeRef}
            aria-hidden="true"
            className="display-dot select-none whitespace-nowrap text-center text-[clamp(7rem,30vw,22rem)] leading-[0.9] tracking-[0.06em] text-[#36FE35]"
          >
            404
          </p>
        </div>

        <div className="grid gap-10 pb-8 md:grid-cols-[1fr_auto] md:items-end">
          <div ref={copyRef} className="max-w-sm space-y-4">
            <span className="pill-outline">page not found</span>
            <h1 className="display-quiet text-[clamp(1.5rem,2.6vw,2rem)] leading-tight">
              We couldn&apos;t find the page you were looking for.
            </h1>
            <p className="text-[15px] leading-relaxed text-[#16191a]/55">
              The link may be outdated, or the page moved while we were busy shaving
              milliseconds off frame times.
            </p>
            <a
              href="/"
              className="group inline-flex items-center gap-2 rounded-full bg-[#16191a] px-7 py-3.5 text-sm font-semibold text-white transition-all duration-300 hover:-translate-y-0.5 hover:bg-black"
            >
              Back to home
              <ArrowUpRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </a>
          </div>

          <div ref={linksRef} className="flex flex-wrap gap-2 md:justify-end">
            {quickLinks.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="rounded-full border border-[#16191a]/12 bg-white/70 px-5 py-2.5 text-sm font-semibold text-[#16191a] backdrop-blur-md transition-all duration-300 hover:-translate-y-0.5 hover:border-[#36FE35]"
              >
                {link.label}
              </a>
            ))}
          </div>
        </div>

        <div className="border-t border-[#16191a]/10 pt-5 text-xs text-[#16191a]/40">
          <p className="font-mono uppercase tracking-[0.2em]">error 404 — nothing to optimize here</p>
        </div>
      </div>
    </main>
  );
}
