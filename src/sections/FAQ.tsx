import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { HelpCircle, ChevronDown, MessageCircle, Gamepad2 } from 'lucide-react';

interface FAQItem {
  question: string;
  answer: string;
}

const faqData: FAQItem[] = [
  {
    question: 'Are these tweaks safe to use?',
    answer: 'Yes, all ZXWY V2 tweaks are thoroughly tested and designed to be reversible. We never modify critical system files or disable essential security features like Windows Defender. Each tweak creates an automatic restore point before making changes, allowing you to roll back anytime.',
  },
  {
    question: 'Do I need to disable my antivirus?',
    answer: 'Absolutely not. You should never disable Windows Defender or your antivirus software to use ZXWY V2. Our tool is designed to work alongside your security software. If your antivirus flags ZXWY, simply add it to your exclusions list.',
  },
  {
    question: 'Will I get more FPS in games?',
    answer: 'While results vary depending on your hardware and current system state, most users see a 10-40% improvement in FPS and significantly reduced stuttering. The tweaks focus on eliminating background processes, optimizing power settings, and reducing input latency.',
  },
  {
    question: 'Can I undo the tweaks?',
    answer: 'Yes! ZXWY V2 automatically creates restore points before applying any changes. You can revert all tweaks with a single click from the application, or use Windows System Restore to go back to a previous state.',
  },
  {
    question: 'What operating systems are supported?',
    answer: 'ZXWY V2 supports Windows 10 (version 1903 and later) and Windows 11. Both 64-bit versions are fully compatible. We do not support Windows 7, 8, or 32-bit systems.',
  },
  {
    question: 'Is ZXWY V2 free?',
    answer: 'Yes! The core ZXWY V2 toolkit is completely free to download and use. We also offer premium plans with additional advanced optimizations and personalized support for users who want the absolute best performance.',
  },
  {
    question: 'How often is ZXWY updated?',
    answer: 'We release updates regularly to add new optimizations, improve compatibility with Windows updates, and fix any reported issues. V2 users receive automatic update notifications within the application.',
  },
  {
    question: 'Will this void my warranty?',
    answer: 'No, using ZXWY V2 will not void your hardware warranty. We only modify software settings within Windows. However, we recommend creating a restore point before making any changes, just to be safe.',
  },
  {
    question: 'Can I use ZXWY on multiple PCs?',
    answer: 'The free version can be used on unlimited personal devices. Premium plans are licensed per user and can be used on multiple PCs you own. Commercial use requires a separate license.',
  },
  {
    question: 'Where can I get support?',
    answer: 'We offer support through our Discord community and Telegram channel. Premium users also get access to priority email support with faster response times.',
  },
];

export function FAQ() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  const toggleQuestion = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section id="faq" className="relative py-24 md:py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-[#35fe34]/5 rounded-full blur-[150px]" />
      </div>

      <div className="section-container relative z-10 max-w-4xl mx-auto">
        {/* Section Header */}
        <motion.div 
          className="text-center max-w-3xl mx-auto mb-16"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#35fe34]/10 border border-[#35fe34]/30 mb-6">
            <HelpCircle className="w-4 h-4 text-[#35fe34]" />
            <span className="text-sm font-medium text-[#35fe34]">FAQ</span>
          </div>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6">
            Frequently Asked <span className="gradient-text">Questions</span>
          </h2>
          <p className="text-lg text-white/60">
            Got questions? We've got answers. If you can't find what you're looking for, 
            feel free to reach out to our community.
          </p>
        </motion.div>

        {/* FAQ List */}
        <div className="space-y-4">
          {faqData.map((item, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.05, duration: 0.5 }}
            >
              <div 
                className={`
                  rounded-2xl border overflow-hidden transition-all duration-300
                  ${openIndex === index 
                    ? 'bg-[#35fe34]/5 border-[#35fe34]/30' 
                    : 'glass-card'
                  }
                `}
              >
                <button
                  onClick={() => toggleQuestion(index)}
                  className="w-full p-5 md:p-6 flex items-center justify-between text-left"
                >
                  <div className="flex items-center gap-4 pr-4">
                    <div className={`
                      w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0
                      ${openIndex === index ? 'bg-[#35fe34]/20' : 'bg-white/5'}
                    `}>
                      <span className="text-[#35fe34] font-bold">{index + 1}</span>
                    </div>
                    <h3 className="font-semibold text-lg">{item.question}</h3>
                  </div>
                  <motion.div
                    animate={{ rotate: openIndex === index ? 180 : 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <ChevronDown className="w-5 h-5 text-white/50 flex-shrink-0" />
                  </motion.div>
                </button>
                
                <AnimatePresence>
                  {openIndex === index && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <div className="px-5 md:px-6 pb-5 md:pb-6 pt-0">
                        <div className="pl-14">
                          <p className="text-white/60 leading-relaxed">
                            {item.answer}
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Contact CTA */}
        <motion.div 
          className="mt-12"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.5, duration: 0.6 }}
        >
          <div className="relative overflow-hidden rounded-2xl glass-card border-[#35fe34]/30 p-8">
            <div className="absolute top-0 right-0 w-64 h-64 bg-[#35fe34]/10 rounded-full blur-[80px]" />
            
            <div className="relative flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-xl bg-[#35fe34]/10 flex items-center justify-center">
                  <MessageCircle className="w-7 h-7 text-[#35fe34]" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold mb-1">Still have questions?</h3>
                  <p className="text-white/50">
                    Join our community for personalized help and support.
                  </p>
                </div>
              </div>
              <div className="flex gap-3">
                <motion.a
                  href="https://discord.gg/UQmBUXct"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-6 py-3 rounded-xl bg-[#5865F2] hover:bg-[#4752C4] text-white font-medium transition-all duration-300"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Gamepad2 className="w-5 h-5" />
                  Join Discord
                </motion.a>
                <motion.a
                  href="https://t.me/ZXWYTWEAKING"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-6 py-3 rounded-xl bg-[#0088cc] hover:bg-[#0077b3] text-white font-medium transition-all duration-300"
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <MessageCircle className="w-5 h-5" />
                  Telegram
                </motion.a>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
