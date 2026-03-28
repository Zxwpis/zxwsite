import { useState } from 'react';
import { motion } from 'framer-motion';
import { Download as DownloadIcon, Check, AlertTriangle, ExternalLink, Copy, CheckCircle2, MessageCircle, Gamepad2 } from 'lucide-react';

const requirements = [
  'Windows 10 or Windows 11',
  'Administrator privileges',
  'Internet connection for updates',
  '50MB free disk space',
];

const steps = [
  {
    step: 1,
    title: 'Download',
    description: 'Get ZXWY V2 from our secure Google Drive folder.',
  },
  {
    step: 2,
    title: 'Extract',
    description: 'Extract the ZIP file to your desired location.',
  },
  {
    step: 3,
    title: 'Run',
    description: 'Right-click and run ZXWY_V2.exe as Administrator.',
  },
  {
    step: 4,
    title: 'Optimize',
    description: 'Select your desired tweaks and apply them.',
  },
];

export function Download() {
  const [copied, setCopied] = useState(false);

  const handleCopyLink = () => {
    navigator.clipboard.writeText('https://drive.google.com/drive/folders/17UcwGUs-j4MrOIpu04aaLiXbC-eahWQM?usp=drive_link');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="download" className="relative py-24 md:py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-[#35fe34]/5 rounded-full blur-[150px]" />
      </div>

      <div className="section-container relative z-10">
        {/* Section Header */}
        <motion.div 
          className="text-center max-w-3xl mx-auto mb-16"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#35fe34]/10 border border-[#35fe34]/30 mb-6">
            <DownloadIcon className="w-4 h-4 text-[#35fe34]" />
            <span className="text-sm font-medium text-[#35fe34]">Get Started</span>
          </div>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6 text-display">
            Download <span className="gradient-text">ZXWY V2</span>
          </h2>
          <p className="text-lg text-white/60">
            Get the latest version of ZXWY V2 for free. Start optimizing your PC 
            in minutes with our easy-to-use toolkit.
          </p>
        </motion.div>

        <div className="grid lg:grid-cols-2 gap-12 items-start max-w-6xl mx-auto">
          {/* Left - Download Card */}
          <motion.div
            initial={{ opacity: 0, x: -40 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, ease: [0.23, 1, 0.32, 1] }}
          >
            <div className="relative">
              {/* Glow */}
              <div className="absolute -inset-4 bg-[#35fe34]/20 rounded-3xl blur-2xl opacity-50" />
              
              {/* Card */}
              <div className="relative glass-card p-8">
                {/* Version Badge */}
                <div className="flex items-center justify-between mb-8">
                  <div className="flex items-center gap-4">
                    <img 
                      src="/logo.png" 
                      alt="ZXWY V2 Logo" 
                      className="w-14 h-14 object-contain"
                      style={{ 
                        imageRendering: 'crisp-edges',
                        filter: 'drop-shadow(0 0 8px rgba(53,254,52,0.4))',
                      }}
                    />
                    <div>
                      <h3 className="text-2xl font-bold text-display tracking-wide">ZXWY V2</h3>
                      <p className="text-sm text-white/50">Latest Version</p>
                    </div>
                  </div>
                  <div className="px-4 py-1.5 rounded-full bg-[#35fe34]/20 border border-[#35fe34]/40 text-[#35fe34] text-sm font-semibold">
                    Free
                  </div>
                </div>

                {/* File Info */}
                <div className="space-y-3 mb-8 p-5 bg-white/5">
                  {[
                    { label: 'Version', value: '2.0.0' },
                    { label: 'File Size', value: '~15 MB' },
                    { label: 'Format', value: 'ZIP Archive' },
                    { label: 'Updated', value: 'February 2025' },
                  ].map((item) => (
                    <div key={item.label} className="flex justify-between text-sm">
                      <span className="text-white/50">{item.label}</span>
                      <span className="font-medium text-white">{item.value}</span>
                    </div>
                  ))}
                </div>

                {/* Download Button */}
                <motion.a
                  href="https://drive.google.com/drive/folders/17UcwGUs-j4MrOIpu04aaLiXbC-eahWQM?usp=drive_link"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block w-full"
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <button className="w-full btn-neon gap-3 text-base py-4">
                    <DownloadIcon className="w-5 h-5" />
                    Download from Google Drive
                    <ExternalLink className="w-4 h-4 ml-auto" />
                  </button>
                </motion.a>

                {/* Copy Link */}
                <motion.button
                  onClick={handleCopyLink}
                  className="w-full mt-3 flex items-center justify-center gap-2 py-3.5 px-4 border border-white/10 hover:border-[#35fe34]/50 hover:bg-[#35fe34]/5 transition-all duration-300 text-sm text-white/60"
                  whileHover={{ scale: 1.01 }}
                  whileTap={{ scale: 0.99 }}
                >
                  {copied ? (
                    <>
                      <CheckCircle2 className="w-4 h-4 text-[#35fe34]" />
                      Link copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4" />
                      Copy download link
                    </>
                  )}
                </motion.button>

                {/* Warning */}
                <div className="flex items-start gap-3 mt-6 p-4 bg-yellow-500/10 border border-yellow-500/30">
                  <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <div className="text-sm">
                    <p className="font-medium text-yellow-500 mb-1">Important</p>
                    <p className="text-white/60">
                      Always create a system restore point before applying tweaks. 
                      Use at your own risk.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Right - Installation Steps */}
          <motion.div 
            className="space-y-8"
            initial={{ opacity: 0, x: 40 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, delay: 0.1, ease: [0.23, 1, 0.32, 1] }}
          >
            {/* Requirements */}
            <div>
              <h3 className="text-xl font-semibold mb-5 flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-[#35fe34]/10 flex items-center justify-center">
                  <Check className="w-4 h-4 text-[#35fe34]" />
                </div>
                System Requirements
              </h3>
              <div className="space-y-3">
                {requirements.map((req, index) => (
                  <motion.div 
                    key={req}
                    className="flex items-center gap-3 p-3 glass-card"
                    initial={{ opacity: 0, x: 20 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.2 + index * 0.1 }}
                  >
                    <div className="w-5 h-5 rounded-full bg-[#35fe34]/20 flex items-center justify-center flex-shrink-0">
                      <Check className="w-3 h-3 text-[#35fe34]" />
                    </div>
                    <span className="text-white/70">{req}</span>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Steps */}
            <div>
              <h3 className="text-xl font-semibold mb-5">Installation Steps</h3>
              <div className="space-y-4">
                {steps.map((step, index) => (
                  <motion.div
                    key={step.step}
                    className="flex items-start gap-4 p-4 glass-card hover:border-[#35fe34]/30 transition-all duration-300"
                    initial={{ opacity: 0, x: 20 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.3 + index * 0.1 }}
                    whileHover={{ x: 5 }}
                  >
                    <div className="w-10 h-10 rounded-lg bg-[#35fe34]/10 flex items-center justify-center flex-shrink-0">
                      <span className="text-[#35fe34] font-bold">{step.step}</span>
                    </div>
                    <div>
                      <h4 className="font-medium mb-1">{step.title}</h4>
                      <p className="text-sm text-white/50">{step.description}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Support */}
            <div className="p-5 glass-card border-[#35fe34]/30">
              <p className="text-sm text-white/50 mb-3">Need help?</p>
              <div className="flex gap-3">
                <motion.a
                  href="https://discord.gg/UQmBUXct"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#5865F2]/10 hover:bg-[#5865F2]/20 border border-[#5865F2]/30 text-[#5865F2] text-sm font-medium transition-all duration-300"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Gamepad2 className="w-4 h-4" />
                  Discord
                </motion.a>
                <motion.a
                  href="https://t.me/ZXWYTWEAKING"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#0088cc]/10 hover:bg-[#0088cc]/20 border border-[#0088cc]/30 text-[#0088cc] text-sm font-medium transition-all duration-300"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <MessageCircle className="w-4 h-4" />
                  Telegram
                </motion.a>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
