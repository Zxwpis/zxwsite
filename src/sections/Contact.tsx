import { useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowUpRight, CheckCircle2, Clock, Loader2, Mail, Send, ShieldCheck } from 'lucide-react';
import { FaDiscord, FaTelegramPlane } from 'react-icons/fa';
import emailjs from '@emailjs/browser';
import { toast } from 'sonner';
import { useSectionReveal } from '../lib/anim';
import { HeadingFlip } from '../components/HeadingFlip';
import { DISCORD_INVITE_URL } from '../config/links';

const contactChannels = [
  {
    icon: FaDiscord,
    name: 'Discord',
    handle: 'Community support',
    link: DISCORD_INVITE_URL,
    external: true,
    tone: 'ink' as const,
  },
  {
    icon: FaTelegramPlane,
    name: 'Telegram',
    handle: 'Fastest response',
    link: 'https://t.me/ZXWYTWEAKING',
    external: true,
    tone: 'lime' as const,
  },
  {
    icon: Mail,
    name: 'Email',
    handle: 'Via the form',
    link: '#contact-form',
    external: false,
    tone: 'ink' as const,
  },
];

const stats = [
  { icon: Clock, value: '< 24h', label: 'Response Time' },
  { icon: ShieldCheck, value: '100%', label: 'Real Support' },
];

interface FormData {
  name: string;
  email: string;
  message: string;
}

interface FormErrors {
  name?: string;
  email?: string;
  message?: string;
}

const FIELD_LIMITS = {
  name: 80,
  email: 254,
  message: 2000,
} as const;

// Strips anything that looks like markup (tags, HTML entities, script/event handlers) so a
// visitor can't inject HTML/JS through the form — the sanitized value is what gets validated,
// shown back in the UI and sent to EmailJS.
function sanitizeInput(value: string): string {
  return value
    // drop full tags first, including their content for <script>/<style>
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    // strip any remaining tags (e.g. <img onerror=...>, <a href="javascript:...">)
    .replace(/<[^>]*>/g, '')
    // neutralize dangerous URI schemes and inline event handlers left as plain text
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
    // collapse the raw special characters HTML parses into markup
    .replace(/[<>]/g, '')
    // drop control characters
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '')
    .replace(/\s{3,}/g, '  ');
}

// HTML-escapes a value right before it leaves the app, so even if the EmailJS template ever
// renders fields as HTML, no markup from user input can execute.
function escapeForEmail(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function Contact() {
  const ref = useSectionReveal();
  const [formData, setFormData] = useState<FormData>({
    name: '',
    email: '',
    message: '',
  });
  const [errors, setErrors] = useState<FormErrors>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);

  const validateForm = (): boolean => {
    const newErrors: FormErrors = {};
    const name = formData.name.trim();
    const email = formData.email.trim();
    const message = formData.message.trim();

    if (!name) {
      newErrors.name = 'Name is required';
    } else if (name.length < 2) {
      newErrors.name = 'Name must be at least 2 characters';
    } else if (name.length > FIELD_LIMITS.name) {
      newErrors.name = `Name must be under ${FIELD_LIMITS.name} characters`;
    } else if (!/^[\p{L}\p{M}\d\s'.-]+$/u.test(name)) {
      newErrors.name = 'Name contains characters that are not allowed';
    }

    if (!email) {
      newErrors.email = 'Email is required';
    } else if (email.length > FIELD_LIMITS.email) {
      newErrors.email = 'Email address is too long';
    } else {
      // RFC-5321-friendly, still deliberately simple/safe (no backtracking blow-ups, no HTML chars).
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
      if (!emailRegex.test(email)) {
        newErrors.email = 'Please enter a valid email address';
      }
    }

    if (!message) {
      newErrors.message = 'Message is required';
    } else if (message.length < 10) {
      newErrors.message = 'Message must be at least 10 characters';
    } else if (message.length > FIELD_LIMITS.message) {
      newErrors.message = `Message must be under ${FIELD_LIMITS.message} characters`;
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      toast.error('Please fix the errors in the form');
      return;
    }

    setIsSubmitting(true);

    try {
      // Messages are delivered straight to zxwytweaking@gmail.com via EmailJS — no backend needed.
      // The recipient address is configured inside the EmailJS template itself (see .env.example
      // for the one-time setup), not passed from the code, so it can't be spoofed by a visitor.
      const SERVICE_ID = import.meta.env.VITE_EMAILJS_SERVICE_ID;
      const TEMPLATE_ID = import.meta.env.VITE_EMAILJS_TEMPLATE_ID;
      const PUBLIC_KEY = import.meta.env.VITE_EMAILJS_PUBLIC_KEY;

      if (!SERVICE_ID || !TEMPLATE_ID || !PUBLIC_KEY) {
        throw new Error('EmailJS environment variables are not configured');
      }

      // Escape one more time right before sending — belt-and-suspenders in case the EmailJS
      // template ever renders a field as raw HTML instead of plain text.
      await emailjs.send(
        SERVICE_ID,
        TEMPLATE_ID,
        {
          title: 'New contact form message',
          name: escapeForEmail(formData.name.trim()),
          email: escapeForEmail(formData.email.trim()),
          message: escapeForEmail(formData.message.trim()),
          time: new Date().toLocaleString(),
        },
        { publicKey: PUBLIC_KEY },
      );

      setIsSubmitted(true);
      setFormData({ name: '', email: '', message: '' });
      toast.success('Message sent successfully! We will get back to you soon.');

      // Reset success message after 5 seconds
      setTimeout(() => setIsSubmitted(false), 5000);
    } catch (error) {
      console.error('Contact form error:', error);
      toast.error('Failed to send message. Please try again later or reach out on Discord.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    const limit = FIELD_LIMITS[name as keyof FormData] ?? Infinity;
    // Sanitize as the user types so markup/script content never even lands in state,
    // and hard-cap length as an extra guard against oversized/spam payloads.
    const cleanValue = sanitizeInput(value).slice(0, limit);
    setFormData((prev) => ({ ...prev, [name]: cleanValue }));
    // Clear error when user starts typing
    if (errors[name as keyof FormErrors]) {
      setErrors((prev) => ({ ...prev, [name]: undefined }));
    }
  };

  const fieldClass = (hasError?: string) =>
    [
      'w-full rounded-2xl border bg-white/70 px-4 py-3.5 text-[15px] text-[#16191a] outline-none transition-all duration-300',
      'placeholder:text-[#16191a]/35',
      'focus:border-[#36FE35] focus:ring-2 focus:ring-[#36FE35]/35',
      hasError ? 'border-[#16191a]/40' : 'border-[#16191a]/10',
    ].join(' ');

  return (
    <section id="contact" ref={ref} className="section-shell bg-transparent">
      <div className="section-glow bottom-0 h-[480px] w-[780px] opacity-50" aria-hidden="true" />

      <div className="section-container relative z-10">
        <div data-reveal className="section-head">
          <span className="pill-outline">
            <Mail className="h-3.5 w-3.5" />
            Get in touch
          </span>
          <HeadingFlip
            className="section-title"
            front={[{ text: 'Contact ' }, { text: 'support', lime: true }]}
            back={[{ text: 'Real humans, ' }, { text: 'real fast', lime: true }]}
          />
          <p className="section-lede">
            Need help with ZXWY V3? Our community and support team are here to assist you.
          </p>
        </div>

        <div data-reveal className="mb-10 flex flex-wrap items-center justify-center gap-3">
          {stats.map((stat) => (
            <div
              key={stat.label}
              className="inline-flex items-center gap-3 rounded-full border border-[#16191a]/10 bg-white/70 px-4 py-2.5 backdrop-blur-md"
            >
              <stat.icon className="h-4 w-4 text-[#16191a]" />
              <span className="text-sm font-semibold text-[#16191a]">{stat.value}</span>
              <span className="text-xs font-medium uppercase tracking-[0.16em] text-[#16191a]/45">
                {stat.label}
              </span>
            </div>
          ))}
        </div>

        <div className="grid gap-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,0.85fr)] lg:gap-6">
          {/* Form card */}
          <div data-reveal className="card-paper hover:translate-y-0" id="contact-form">
            <div className="mb-8">
              <h3 className="display-quiet text-2xl text-[#16191a] md:text-[1.75rem]">
                Send a message
              </h3>
              <p className="mt-2 text-[15px] leading-relaxed text-[#16191a]/55">
                Fill out the form below and we&apos;ll get back to you as soon as possible.
              </p>
            </div>

            {isSubmitted ? (
              <motion.div
                className="flex flex-col items-center py-14 text-center"
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
              >
                <div className="icon-chip mb-5 bg-[#36FE35] text-[#16191a]">
                  <CheckCircle2 className="h-6 w-6" />
                </div>
                <h4 className="display-quiet text-2xl text-[#16191a]">Message sent!</h4>
                <p className="mt-2 max-w-sm text-[15px] leading-relaxed text-[#16191a]/60">
                  Thank you for reaching out. We&apos;ll respond within 24 hours.
                </p>
              </motion.div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5" noValidate>
                <div className="space-y-2">
                  <label htmlFor="contact-name" className="block text-sm font-medium text-[#16191a]/70">
                    Your Name
                  </label>
                  <input
                    id="contact-name"
                    type="text"
                    name="name"
                    placeholder="John Doe"
                    value={formData.name}
                    onChange={handleChange}
                    autoComplete="name"
                    maxLength={FIELD_LIMITS.name}
                    aria-invalid={Boolean(errors.name)}
                    aria-describedby={errors.name ? 'contact-name-error' : undefined}
                    className={fieldClass(errors.name)}
                  />
                  {errors.name && (
                    <p id="contact-name-error" className="text-xs font-medium text-[#16191a]/70">
                      {errors.name}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <label htmlFor="contact-email" className="block text-sm font-medium text-[#16191a]/70">
                    Email Address
                  </label>
                  <input
                    id="contact-email"
                    type="email"
                    name="email"
                    placeholder="john@example.com"
                    value={formData.email}
                    onChange={handleChange}
                    autoComplete="email"
                    maxLength={FIELD_LIMITS.email}
                    aria-invalid={Boolean(errors.email)}
                    aria-describedby={errors.email ? 'contact-email-error' : undefined}
                    className={fieldClass(errors.email)}
                  />
                  {errors.email && (
                    <p id="contact-email-error" className="text-xs font-medium text-[#16191a]/70">
                      {errors.email}
                    </p>
                  )}
                </div>

                <div className="space-y-2">
                  <label htmlFor="contact-message" className="block text-sm font-medium text-[#16191a]/70">
                    Message
                  </label>
                  <textarea
                    id="contact-message"
                    name="message"
                    placeholder="How can we help you?"
                    value={formData.message}
                    onChange={handleChange}
                    rows={5}
                    maxLength={FIELD_LIMITS.message}
                    aria-invalid={Boolean(errors.message)}
                    aria-describedby={errors.message ? 'contact-message-error' : undefined}
                    className={`${fieldClass(errors.message)} resize-none`}
                  />
                  {errors.message && (
                    <p id="contact-message-error" className="text-xs font-medium text-[#16191a]/70">
                      {errors.message}
                    </p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-full bg-[#36FE35] px-7 py-3.5 text-sm font-semibold text-[#16191A] transition-all duration-300 hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-70 disabled:hover:translate-y-0"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Sending...
                    </>
                  ) : (
                    <>
                      <Send className="h-4 w-4" />
                      Send Message
                    </>
                  )}
                </button>

                <p className="text-center text-xs text-[#16191a]/45">
                  By submitting this form, you agree to our privacy policy.
                </p>
              </form>
            )}
          </div>

          {/* Channel column */}
          <div className="flex flex-col gap-4">
            {contactChannels.map((channel) => {
              const cardTone = channel.tone === 'lime' ? 'card-lime' : 'card-ink';
              const chipTone =
                channel.tone === 'lime'
                  ? 'bg-[#16191a] text-[#36FE35]'
                  : 'bg-white/10 text-[#36FE35]';
              const handleTone = channel.tone === 'lime' ? 'text-[#16191a]/70' : 'text-white/55';
              const arrowTone = channel.tone === 'lime' ? 'text-[#16191a]' : 'text-white/70';

              return (
                <a
                  key={channel.name}
                  data-reveal
                  href={channel.link}
                  target={channel.external ? '_blank' : undefined}
                  rel={channel.external ? 'noopener noreferrer' : undefined}
                  onClick={
                    channel.external
                      ? undefined
                      : (e) => {
                          e.preventDefault();
                          document.querySelector('#contact-form')?.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start',
                          });
                        }
                  }
                  className={`group ${cardTone} flex items-center gap-4 !p-5`}
                >
                  <span className={`icon-chip flex-shrink-0 ${chipTone}`}>
                    <channel.icon className="h-5 w-5" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-[15px] font-semibold tracking-tight">{channel.name}</p>
                    <p className={`text-sm ${handleTone}`}>{channel.handle}</p>
                  </div>
                  <ArrowUpRight
                    className={`h-4 w-4 flex-shrink-0 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 ${arrowTone}`}
                  />
                </a>
              );
            })}

            <div data-reveal className="card-paper mt-1 hover:translate-y-0 !p-6">
              <div className="mb-4 flex items-center gap-2">
                <Clock className="h-4 w-4 text-[#16191a]" />
                <h4 className="text-sm font-semibold uppercase tracking-[0.16em] text-[#16191a]">
                  Support Hours
                </h4>
              </div>
              <p className="mb-4 text-sm leading-relaxed text-[#16191a]/60">
                Our community is active 24/7, but official support responses are typically provided during:
              </p>
              <div className="space-y-3 text-sm">
                <div className="flex items-center justify-between gap-4 border-b border-[#16191a]/10 pb-3">
                  <span className="font-medium text-[#16191a]">Monday - Friday</span>
                  <span className="font-mono text-xs tracking-wide text-[#16191a]/55">
                    9:00 AM - 6:00 PM UTC
                  </span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="font-medium text-[#16191a]">Weekend</span>
                  <span className="font-mono text-xs tracking-wide text-[#16191a]/55">
                    Community Support Only
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
