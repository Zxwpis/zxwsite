import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, MessageCircle, Gamepad2 } from 'lucide-react';

const navLinks = [
  { href: '#hero', label: 'Home' },
  { href: '#features', label: 'Features' },
  { href: '#download', label: 'Download' },
  { href: '#changelog', label: 'Changelog' },
  { href: '#pricing', label: 'Pricing' },
  { href: '#faq', label: 'FAQ' },
  { href: '#contact', label: 'Contact' },
];

export function Header() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeSection, setActiveSection] = useState('hero');

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
      
      // Update active section based on scroll position
      const sections = navLinks.map(link => link.href.replace('#', ''));
      for (const section of sections.reverse()) {
        const element = document.getElementById(section);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            setActiveSection(section);
            break;
          }
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = (href: string) => {
    const element = document.querySelector(href);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
    setIsMobileMenuOpen(false);
  };

  return (
    <>
      <motion.header 
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${
          isScrolled ? 'py-3' : 'py-5'
        }`}
        initial={{ y: -100, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
      >
        <div className="section-container">
          <div 
            className={`
              flex items-center justify-between px-6 py-3 rounded-2xl
              transition-all duration-500
              ${isScrolled 
                ? 'bg-[#0a0a0a]/90 backdrop-blur-xl border border-white/10 shadow-2xl shadow-black/50' 
                : 'bg-transparent'
              }
            `}
          >
            {/* Logo */}
            <motion.a 
              href="#hero" 
              onClick={(e) => { e.preventDefault(); scrollToSection('#hero'); }}
              className="flex items-center gap-3 group"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              <div className="relative flex-shrink-0 p-1">
                <img 
                  src="/logo.png" 
                  alt="ZXWY V2 Logo" 
                  className="relative w-10 h-10 object-contain"
                  style={{ 
                    imageRendering: 'crisp-edges',
                    filter: 'drop-shadow(0 0 8px rgba(53,254,52,0)) ',
                    transition: 'filter 0.3s ease',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.filter = 'drop-shadow(0 0 10px rgba(53,254,52,0.7))')}
                  onMouseLeave={e => (e.currentTarget.style.filter = 'drop-shadow(0 0 8px rgba(53,254,52,0))')}
                />
              </div>
              <div className="flex flex-col">
                <span className="text-lg font-bold tracking-widest text-display">
                  ZXWY <span className="text-[#35fe34]">V2</span>
                </span>
                <span className="text-[9px] text-white/40 -mt-0.5 tracking-[0.2em] uppercase">
                  PC Optimization
                </span>
              </div>
            </motion.a>

            {/* Desktop Navigation */}
            <nav className="hidden lg:flex items-center gap-1">
              {navLinks.map((link, index) => (
                <motion.a
                  key={link.href}
                  href={link.href}
                  onClick={(e) => { e.preventDefault(); scrollToSection(link.href); }}
                  className={`
                    relative px-4 py-2 text-sm font-medium rounded-lg transition-all duration-300
                    ${activeSection === link.href.replace('#', '')
                      ? 'text-[#35fe34]'
                      : 'text-white/60 hover:text-white'
                    }
                  `}
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 + index * 0.05 }}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  {link.label}
                  {activeSection === link.href.replace('#', '') && (
                    <motion.div
                      layoutId="activeNav"
                      className="absolute inset-0 bg-[#35fe34]/10 rounded-lg -z-10"
                      transition={{ type: 'spring', bounce: 0.2, duration: 0.6 }}
                    />
                  )}
                </motion.a>
              ))}
            </nav>

            {/* Right Side Actions */}
            <div className="flex items-center gap-3">
              {/* Social Links - Desktop */}
              <div className="hidden md:flex items-center gap-2">
                <motion.a
                  href="https://t.me/ZXWYTWEAKING"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2.5 text-white/50 hover:text-[#35fe34] hover:bg-white/5 transition-all duration-300"
                  aria-label="Telegram"
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                >
                  <MessageCircle className="w-5 h-5" />
                </motion.a>
                <motion.a
                  href="https://discord.gg/UQmBUXct"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-2.5 text-white/50 hover:text-[#35fe34] hover:bg-white/5 transition-all duration-300"
                  aria-label="Discord"
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                >
                  <Gamepad2 className="w-5 h-5" />
                </motion.a>
              </div>

              {/* CTA Button */}
              <motion.a
                href="#download"
                onClick={(e) => { e.preventDefault(); scrollToSection('#download'); }}
                className="hidden sm:flex btn-neon text-xs px-4 py-2"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                Download
              </motion.a>

              {/* Mobile Menu Toggle */}
              <motion.button
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                className="lg:hidden p-2.5 text-white/70 hover:text-white hover:bg-white/5 transition-all duration-300"
                aria-label="Toggle menu"
                whileHover={{ scale: 1.1 }}
                whileTap={{ scale: 0.9 }}
              >
                {isMobileMenuOpen ? (
                  <X className="w-5 h-5" />
                ) : (
                  <Menu className="w-5 h-5" />
                )}
              </motion.button>
            </div>
          </div>
        </div>
      </motion.header>

      {/* Mobile Menu */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 lg:hidden"
          >
            {/* Backdrop */}
            <motion.div 
              className="absolute inset-0 bg-black/80 backdrop-blur-xl"
              onClick={() => setIsMobileMenuOpen(false)}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            />
            
            {/* Menu Content */}
            <motion.div
              className="absolute top-24 left-4 right-4 glass-card p-6"
              initial={{ opacity: 0, y: -20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -20, scale: 0.95 }}
              transition={{ type: 'spring', bounce: 0.3, duration: 0.5 }}
            >
              <nav className="flex flex-col gap-2">
                {navLinks.map((link, index) => (
                  <motion.a
                    key={link.href}
                    href={link.href}
                    onClick={(e) => { e.preventDefault(); scrollToSection(link.href); }}
                    className={`
                      px-4 py-3 text-lg font-medium rounded-xl transition-all duration-300
                      ${activeSection === link.href.replace('#', '')
                        ? 'text-[#35fe34] bg-[#35fe34]/10'
                        : 'text-white/70 hover:text-white hover:bg-white/5'
                      }
                    `}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05 }}
                  >
                    {link.label}
                  </motion.a>
                ))}
              </nav>
              
              {/* Mobile Social Links */}
              <div className="flex items-center gap-3 mt-6 pt-6 border-t border-white/10">
                <a
                  href="https://t.me/ZXWYTWEAKING"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#0088cc]/10 hover:bg-[#0088cc]/20 border border-[#0088cc]/30 text-[#0088cc] font-medium transition-all duration-300"
                >
                  <MessageCircle className="w-5 h-5" />
                  Telegram
                </a>
                <a
                  href="https://discord.gg/UQmBUXct"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#5865F2]/10 hover:bg-[#5865F2]/20 border border-[#5865F2]/30 text-[#5865F2] font-medium transition-all duration-300"
                >
                  <Gamepad2 className="w-5 h-5" />
                  Discord
                </a>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
