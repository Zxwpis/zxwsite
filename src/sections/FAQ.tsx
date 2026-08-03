import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ArrowUpRight, Plus } from 'lucide-react';
import { useSectionReveal } from '../lib/anim';
import { HeadingFlip } from '../components/HeadingFlip';

interface FAQItem {
  question: string;
  answer: string;
}

const faqData: FAQItem[] = [
  {
    question: 'Are these tweaks safe to use?',
    answer: 'Yes, all ZXWY V3 tweaks are thoroughly tested and designed to be reversible. We never modify critical system files or disable essential security features like Windows Defender. Each tweak creates an automatic restore point before making changes, allowing you to roll back anytime.',
  },
  {
    question: 'Do I need to disable my antivirus?',
    answer: 'Absolutely not. You should never disable Windows Defender or your antivirus software to use ZXWY V3. Our tool is designed to work alongside your security software. If your antivirus flags ZXWY, simply add it to your exclusions list.',
  },
  {
    question: 'Will I get more FPS in games?',
    answer: 'While results vary depending on your hardware and current system state, most users see a 10-40% improvement in FPS and significantly reduced stuttering. The tweaks focus on eliminating background processes, optimizing power settings, and reducing input latency.',
  },
  {
    question: 'Can I undo the tweaks?',
    answer: 'Yes! ZXWY V3 automatically creates restore points before applying any changes. You can revert all tweaks with a single click from the application, or use Windows System Restore to go back to a previous state.',
  },
  {
    question: 'What operating systems are supported?',
    answer: 'ZXWY V3 supports Windows 10 (version 1903 and later) and Windows 11. Both 64-bit versions are fully compatible. We do not support Windows 7, 8, or 32-bit systems.',
  },
  {
    question: 'Is ZXWY V3 a subscription?',
    answer: 'No — ZXWY V3 is a one-time purchase across three tiers (Standard, Max, Ultimate). There are no recurring fees or hidden charges, ever.',
  },
  {
    question: 'How often is ZXWY updated?',
    answer: 'We release updates regularly to add new optimizations, improve compatibility with Windows updates, and fix any reported issues. V3 users receive automatic update notifications within the application.',
  },
  {
    question: 'Will this void my warranty?',
    answer: 'No, using ZXWY V3 will not void your hardware warranty. We only modify software settings within Windows. However, we recommend creating a restore point before making any changes, just to be safe.',
  },
  {
    question: 'Can I use ZXWY on multiple PCs?',
    answer: 'Each license is tied to a limited number of personal devices depending on your tier. Commercial use requires a separate license.',
  },
  {
    question: 'Where can I get support?',
    answer: 'We offer support through our Discord community and Telegram channel. Max and Ultimate users also get access to priority email support with faster response times.',
  },
];

export function FAQ() {
  const ref = useSectionReveal();
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  const toggleQuestion = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  const scrollToContact = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    document.querySelector('#contact')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <section id="faq" ref={ref} className="section-shell bg-transparent">
      <div className="section-glow top-1/3 h-[420px] w-[720px] opacity-60" aria-hidden="true" />

      <div className="section-container relative z-10">
        <div className="grid gap-12 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.2fr)] lg:gap-16">
          {/* Sticky editorial header */}
          <div data-reveal className="lg:sticky lg:top-28 lg:self-start">
            <span className="pill-outline">FAQ</span>
            <HeadingFlip
              className="section-title mt-6 text-left"
              front={[{ text: 'Frequently asked ' }, { text: 'questions', lime: true }]}
              back={[{ text: "Can't find it? " }, { text: 'Just ask', lime: true }]}
            />
            <p className="section-lede mx-0 mt-5 text-left">
              Got questions? We&apos;ve got answers. If you can&apos;t find what you&apos;re looking for,
              don&apos;t hesitate to reach out to our community.
            </p>
            <a
              href="#contact"
              onClick={scrollToContact}
              className="group mt-8 inline-flex items-center gap-2 text-sm font-semibold text-[#16191a] transition-colors duration-300 hover:text-[#16191a]/70"
            >
              Still stuck? Talk to us
              <ArrowUpRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </a>
          </div>

          {/* Accordion list */}
          <div className="space-y-3">
            {faqData.map((item, index) => {
              const isOpen = openIndex === index;
              const number = String(index + 1).padStart(2, '0');

              return (
                <div
                  key={item.question}
                  data-reveal
                  className="card-paper !p-0 hover:translate-y-0"
                >
                  <button
                    type="button"
                    onClick={() => toggleQuestion(index)}
                    aria-expanded={isOpen}
                    className="flex w-full items-center gap-4 px-5 py-5 text-left md:gap-5 md:px-6 md:py-6"
                  >
                    <span className="index-tag flex-shrink-0">{number}</span>
                    <h3 className="flex-1 text-[15px] font-semibold leading-snug text-[#16191a] md:text-base">
                      {item.question}
                    </h3>
                    <span
                      className="grid h-9 w-9 flex-shrink-0 place-items-center rounded-full bg-[#16191a] text-white transition-transform duration-300"
                      style={{ transform: isOpen ? 'rotate(45deg)' : 'rotate(0deg)' }}
                      aria-hidden="true"
                    >
                      <Plus className="h-4 w-4" />
                    </span>
                  </button>

                  <AnimatePresence initial={false}>
                    {isOpen && (
                      <motion.div
                        key="content"
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.32, ease: [0.23, 1, 0.32, 1] }}
                        className="overflow-hidden"
                      >
                        <div className="border-t border-[#16191a]/10 px-5 pb-5 pt-4 md:px-6 md:pb-6">
                          <p className="max-w-2xl pl-0 text-[15px] leading-relaxed text-[#16191a]/65 md:pl-[3.25rem]">
                            {item.answer}
                          </p>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
}
