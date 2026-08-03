import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Header } from './sections/Header';
import { Hero } from './sections/Hero';
import { Showcase } from './sections/Showcase';
import { Features } from './sections/Features';
import { Download } from './sections/Download';
import { Changelog } from './sections/Changelog';
import { Pricing } from './sections/Pricing';
import { FAQ } from './sections/FAQ';
import { Contact } from './sections/Contact';
import { Footer } from './sections/Footer';
import { BotCheck } from './components/BotCheck';
import { Toaster } from './components/ui/sonner';
import { PixelGrid } from './components/PixelGrid';
import { ScrollProgress } from './components/ScrollProgress';
import { NotFound } from './pages/NotFound';

/** The site is a single landing page — anything else is a 404. */
const KNOWN_ROUTES = ['/', '/index.html', ''];

function isKnownRoute() {
  if (typeof window === 'undefined') return true;
  const path = window.location.pathname.replace(/\/+$/, '') || '/';
  return KNOWN_ROUTES.includes(path);
}

function App() {
  const [isVerified, setIsVerified] = useState(false);
  const [routeFound] = useState(isKnownRoute);

  useEffect(() => {
    const verified = localStorage.getItem('zxwy_v3_verified') === 'true';
    setIsVerified(verified);
  }, []);

  const handleVerification = () => {
    localStorage.setItem('zxwy_v3_verified', 'true');
    setIsVerified(true);
  };

  if (!routeFound) {
    return (
      <>
        <NotFound />
        <Toaster position="bottom-right" />
      </>
    );
  }

  return (
    <div className="relative min-h-screen bg-white text-[#16191A] overflow-x-hidden">
      {/* Quiet ambient texture behind every section — the same cursor-reactive pixel
          grid used to sit under the (now removed) Kawarp warp gradient. Kept alone so
          the page reads as clean white, letting the Hero's own FaultyTerminal background
          stay the one loud effect on the page. */}
      <div className="absolute inset-0 pointer-events-none z-0 opacity-[0.18]">
        <PixelGrid />
      </div>

      <AnimatePresence>
        {!isVerified && <BotCheck onVerify={handleVerification} />}
      </AnimatePresence>

      <motion.div
        className="relative z-10"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.6 }}
      >
        <ScrollProgress />
        <Header />
        <main>
          <Hero />
          <Showcase />
          <Pricing />
          <Download />
          <Features />
          <Changelog />
          <FAQ />
          <Contact />
        </main>
        <Footer />
      </motion.div>

      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: 'rgba(22, 25, 26, 0.9)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            color: '#ffffff',
            fontFamily: 'Inter, system-ui, sans-serif',
            borderRadius: '1rem',
          },
        }}
      />
    </div>
  );
}

export default App;
