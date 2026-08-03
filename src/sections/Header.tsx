import { useState, useEffect, useRef } from 'react';
import { AnimatePresence, motion as framerMotion } from 'framer-motion';
import { ArrowUpRight, Menu, X } from 'lucide-react';
import { FaDiscord, FaTelegramPlane } from 'react-icons/fa';
import gsap from 'gsap';
import { Flip } from 'gsap/Flip';
import { motionListReveal } from '../lib/anim';
import { DISCORD_INVITE_URL } from '../config/links';

gsap.registerPlugin(Flip);

const reducedMotion = () =>
  typeof window !== 'undefined' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// Kept in the same order the sections actually appear on the page
// (Hero → Pricing → Download → Features → Changelog → FAQ → Contact),
// so the nav reads top-to-bottom the way the site scrolls.
const navLinks = [
  { href: '#hero', label: 'Home' },
  { href: '#pricing', label: 'Pricing' },
  { href: '#features', label: 'Features' },
  { href: '#changelog', label: 'Changelog' },
  { href: '#faq', label: 'FAQ' },
  { href: '#contact', label: 'Contact' },
];

const socials = [
  { icon: FaTelegramPlane, href: 'https://t.me/ZXWYTWEAKING', label: 'Telegram' },
  { icon: FaDiscord, href: DISCORD_INVITE_URL, label: 'Discord' },
];

export function Header() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('hero');
  const navRef = useRef<HTMLElement>(null);
  const indicatorRef = useRef<HTMLSpanElement>(null);
  const linkRefs = useRef<Record<string, HTMLAnchorElement | null>>({});

  useEffect(() => {
    // Motion One trails the nav pills in on mount
    motionListReveal(navRef.current, 'a', 0.25);

    const handleScroll = () => {
      setIsScrolled(window.scrollY > 40);

      const sections = navLinks.map((link) => link.href.replace('#', ''));
      for (const section of [...sections].reverse()) {
        const element = document.getElementById(section);
        if (element && element.getBoundingClientRect().top <= 160) {
          setActiveSection(section);
          break;
        }
      }
    };

    handleScroll();
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    // Signature detail: the active nav pill is one shared lime tile that glides between
    // links via GSAP Flip, instead of every pill re-coloring on its own.
    const moveIndicator = (animate: boolean) => {
      const indicator = indicatorRef.current;
      const activeLink = linkRefs.current[activeSection];
      if (!indicator || !activeLink) return;

      Flip.fit(indicator, activeLink, {
        duration: animate && !reducedMotion() ? 0.45 : 0,
        ease: 'power3.out',
        absolute: true,
      });
    };

    moveIndicator(true);

    const handleResize = () => moveIndicator(false);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [activeSection]);

  const scrollToSection = (href: string) => {
    document.querySelector(href)?.scrollIntoView({ behavior: 'smooth' });
    setIsMobileMenuOpen(false);
  };

  const navPillClass = (href: string) => {
    const isActive = activeSection === href.replace('#', '');
    return `relative z-10 flex h-9 items-center rounded-full px-4 text-[13px] font-semibold transition-colors duration-300 ${
      isActive ? 'text-[#16191A]' : 'text-[#16191a]/60 hover:bg-[#16191a]/[0.06] hover:text-[#16191a]'
    }`;
  };

  return (
    <>
      <framerMotion.header
        className={`fixed inset-x-0 top-0 z-50 transition-all duration-500 ${isScrolled ? 'py-3' : 'py-5'}`}
        initial={{ y: -80, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="mx-auto w-full max-w-[1440px] px-6">
          <div
            className={`flex items-center justify-between gap-4 rounded-full border px-3 py-2 transition-all duration-500 ${
              isScrolled
                ? 'border-[#16191a]/10 bg-white/80 backdrop-blur-2xl'
                : 'border-transparent bg-white/45 backdrop-blur-xl'
            }`}
            style={{
              boxShadow: isScrolled ? '0 18px 50px -30px rgba(22, 25, 26, 0.45)' : 'none',
            }}
          >
            {/* Wordmark */}
            <a
              href="#hero"
              onClick={(e) => { e.preventDefault(); scrollToSection('#hero'); }}
              className="flex flex-shrink-0 items-center gap-2.5 pl-1 pr-2"
            >
              <span className="grid h-9 w-9 place-items-center rounded-full bg-[#16191a]">
                <img src="/White.png" alt="ZXWY V3 logo" className="h-[18px] w-[18px] object-contain" width={18} height={18} />
              </span>
              <span className="hidden text-[15px] font-semibold tracking-tight text-[#16191a] sm:block">
                ZXWY <span className="text-[#36FE35]">V3</span>
              </span>
            </a>

            {/* Desktop navigation — one calm pill language for every link */}
            <nav ref={navRef} className="relative hidden items-center gap-1 lg:flex">
              <span
                ref={indicatorRef}
                aria-hidden="true"
                className="pointer-events-none absolute left-0 top-0 z-0 rounded-full bg-[#36FE35]"
              />
              {navLinks.map((link) => (
                <a
                  key={link.href}
                  ref={(el) => { linkRefs.current[link.href.replace('#', '')] = el; }}
                  href={link.href}
                  onClick={(e) => { e.preventDefault(); scrollToSection(link.href); }}
                  className={navPillClass(link.href)}
                >
                  {link.label}
                </a>
              ))}
            </nav>

            <div className="flex flex-shrink-0 items-center gap-2">
              {socials.map((social) => (
                <a
                  key={social.label}
                  href={social.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={social.label}
                  className="hidden h-9 w-9 place-items-center rounded-full border border-[#16191a]/10 text-[#16191a]/70 transition-all duration-300 hover:border-[#36FE35] hover:bg-[#36FE35] hover:text-[#16191a] sm:grid"
                >
                  <social.icon className="h-4 w-4" />
                </a>
              ))}

              <a
                href="#download"
                onClick={(e) => { e.preventDefault(); scrollToSection('#download'); }}
                className="group flex h-9 items-center gap-1.5 rounded-full bg-[#16191a] px-5 text-[13px] font-semibold text-white transition-all duration-300 hover:bg-black"
              >
                Download
                <ArrowUpRight className="h-3.5 w-3.5 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
              </a>

              <button
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
                aria-expanded={isMobileMenuOpen}
                className="grid h-9 w-9 place-items-center rounded-full bg-[#16191a]/[0.06] text-[#16191a] transition-colors duration-300 hover:bg-[#16191a]/[0.12] lg:hidden"
              >
                {isMobileMenuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
              </button>
            </div>
          </div>
        </div>
      </framerMotion.header>

      {/* Mobile menu */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <framerMotion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 lg:hidden"
          >
            <div
              className="absolute inset-0 bg-[#16191a]/40 backdrop-blur-xl"
              onClick={() => setIsMobileMenuOpen(false)}
            />

            <framerMotion.div
              className="absolute inset-x-4 top-24 overflow-hidden rounded-[26px] border border-[#16191a]/10 bg-white/90 p-4 backdrop-blur-2xl"
              initial={{ opacity: 0, y: -12, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -12, scale: 0.98 }}
              transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
            >
              <div className="flex flex-col gap-1.5">
                {navLinks.map((link) => {
                  const isActive = activeSection === link.href.replace('#', '');
                  return (
                    <a
                      key={link.href}
                      href={link.href}
                      onClick={(e) => { e.preventDefault(); scrollToSection(link.href); }}
                      className={`flex items-center justify-between rounded-2xl px-4 py-3 text-[15px] font-semibold transition-all duration-300 ${
                        isActive
                          ? 'bg-[#36FE35] text-[#16191A]'
                          : 'text-[#16191a]/70 hover:bg-[#16191a]/[0.06] hover:text-[#16191a]'
                      }`}
                    >
                      {link.label}
                      <ArrowUpRight className="h-4 w-4 opacity-40" />
                    </a>
                  );
                })}
              </div>

              <div className="mt-4 flex items-center gap-2 border-t border-[#16191a]/10 pt-4">
                {socials.map((social) => (
                  <a
                    key={social.label}
                    href={social.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={social.label}
                    className="grid h-10 w-10 place-items-center rounded-full border border-[#16191a]/10 text-[#16191a]/70 transition-all duration-300 hover:border-[#36FE35] hover:bg-[#36FE35] hover:text-[#16191a]"
                  >
                    <social.icon className="h-4 w-4" />
                  </a>
                ))}
                <a
                  href="#download"
                  onClick={(e) => { e.preventDefault(); scrollToSection('#download'); }}
                  className="ml-auto flex h-10 items-center rounded-full bg-[#16191a] px-5 text-[13px] font-semibold text-white"
                >
                  Download
                </a>
              </div>
            </framerMotion.div>
          </framerMotion.div>
        )}
      </AnimatePresence>
    </>
  );
}
