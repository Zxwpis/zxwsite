import { motion } from 'framer-motion';
import { Heart, MessageCircle, Gamepad2, Github, Twitter } from 'lucide-react';

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
    { label: 'Discord', href: 'https://discord.gg/UQmBUXct' },
    { label: 'Telegram', href: 'https://t.me/ZXWYTWEAKING' },
  ],
  legal: [
    { label: 'Privacy Policy', href: '#' },
    { label: 'Terms of Service', href: '#' },
    { label: 'Disclaimer', href: '#' },
  ],
};

export function Footer() {
  const scrollToSection = (href: string) => {
    if (href.startsWith('#')) {
      const element = document.querySelector(href);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
      }
    }
  };

  return (
    <footer className="relative pt-20 pb-8 border-t border-white/10">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[600px] h-[300px] bg-[#22c55e]/5 rounded-full blur-[100px]" />
      </div>

      <div className="section-container relative z-10">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-8 lg:gap-12 mb-12">
          {/* Brand */}
          <div className="col-span-2 md:col-span-4 lg:col-span-2">
            <motion.a 
              href="#hero" 
              onClick={(e) => { e.preventDefault(); scrollToSection('#hero'); }}
              className="flex items-center gap-3 mb-4 group"
              whileHover={{ scale: 1.02 }}
            >
              <img 
                src="/logo.png" 
                alt="ZXWY V2 Logo" 
                className="w-10 h-10 rounded-xl object-contain group-hover:shadow-lg group-hover:shadow-[#22c55e]/20 transition-shadow"
                style={{ imageRendering: 'crisp-edges' }}
              />
              <div>
                <span className="text-xl font-bold">ZXWY <span className="text-[#22c55e]">V2</span></span>
              </div>
            </motion.a>
            <p className="text-white/50 text-sm mb-6 max-w-xs">
              The ultimate PC optimization toolkit for gamers. Boost performance, 
              reduce latency, and unlock your system's full potential.
            </p>
            
            {/* Social Links */}
            <div className="flex gap-3">
              {[
                { icon: MessageCircle, href: 'https://t.me/ZXWYTWEAKING', label: 'Telegram', color: '#0088cc' },
                { icon: Gamepad2, href: 'https://discord.gg/UQmBUXct', label: 'Discord', color: '#5865F2' },
                { icon: Github, href: '#', label: 'GitHub', color: '#22c55e' },
                { icon: Twitter, href: '#', label: 'Twitter', color: '#22c55e' },
              ].map((social) => (
                <motion.a
                  key={social.label}
                  href={social.href}
                  target={social.href.startsWith('http') ? '_blank' : undefined}
                  rel={social.href.startsWith('http') ? 'noopener noreferrer' : undefined}
                  className="w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center text-white/50 hover:text-[#22c55e] hover:bg-[#22c55e]/10 transition-all duration-300"
                  aria-label={social.label}
                  whileHover={{ scale: 1.1 }}
                  whileTap={{ scale: 0.9 }}
                >
                  <social.icon className="w-5 h-5" />
                </motion.a>
              ))}
            </div>
          </div>

          {/* Product Links */}
          <div>
            <h4 className="font-semibold mb-4">Product</h4>
            <ul className="space-y-3">
              {footerLinks.product.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    onClick={(e) => { 
                      e.preventDefault(); 
                      scrollToSection(link.href); 
                    }}
                    className="text-sm text-white/50 hover:text-[#22c55e] transition-colors duration-300"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Support Links */}
          <div>
            <h4 className="font-semibold mb-4">Support</h4>
            <ul className="space-y-3">
              {footerLinks.support.map((link) => (
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
                    className="text-sm text-white/50 hover:text-[#22c55e] transition-colors duration-300"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Legal Links */}
          <div>
            <h4 className="font-semibold mb-4">Legal</h4>
            <ul className="space-y-3">
              {footerLinks.legal.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-sm text-white/50 hover:text-[#22c55e] transition-colors duration-300"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-white/10">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <p className="text-sm text-white/40 text-center md:text-left">
              © 2025 ZXWY V2. All rights reserved.
            </p>
            <p className="text-sm text-white/40 flex items-center gap-1">
              Made with <Heart className="w-4 h-4 text-red-500 fill-red-500" /> for the gaming community
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
}
