import { useState } from 'react';
import { motion } from 'framer-motion';
import { Mail, MessageCircle, Gamepad2, Send, CheckCircle2, Clock, Users, Loader2 } from 'lucide-react';
import axios from 'axios';
import { toast } from 'sonner';

const contactMethods = [
  {
    icon: MessageCircle,
    name: 'Telegram',
    description: 'Fastest response time',
    link: 'https://t.me/ZXWYTWEAKING',
    color: 'bg-[#0088cc]/10 text-[#0088cc] border-[#0088cc]/30',
    hoverColor: 'hover:bg-[#0088cc]/20',
  },
  {
    icon: Gamepad2,
    name: 'Discord',
    description: 'Community support',
    link: 'https://discord.gg/UQmBUXct',
    color: 'bg-[#5865F2]/10 text-[#5865F2] border-[#5865F2]/30',
    hoverColor: 'hover:bg-[#5865F2]/20',
  },
];

const stats = [
  { icon: Clock, value: '< 24h', label: 'Response Time' },
  { icon: Users, value: '5k+', label: 'Community Members' },
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

export function Contact() {
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

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    } else if (formData.name.length < 2) {
      newErrors.name = 'Name must be at least 2 characters';
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(formData.email)) {
        newErrors.email = 'Please enter a valid email address';
      }
    }

    if (!formData.message.trim()) {
      newErrors.message = 'Message is required';
    } else if (formData.message.length < 10) {
      newErrors.message = 'Message must be at least 10 characters';
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
      // For demo/development, use mock endpoint
      // In production, replace with actual API endpoint
      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001';
      
      const response = await axios.post(`${API_URL}/api/contact`, formData);

      if (response.data.success) {
        setIsSubmitted(true);
        setFormData({ name: '', email: '', message: '' });
        toast.success('Message sent successfully! We will get back to you soon.');
        
        // Reset success message after 5 seconds
        setTimeout(() => setIsSubmitted(false), 5000);
      } else {
        toast.error(response.data.error || 'Failed to send message');
      }
    } catch (error) {
      console.error('Contact form error:', error);
      
      // Fallback: Show success even if server is not running (for demo)
      // In production, remove this fallback
      if (axios.isAxiosError(error) && !error.response) {
        // Server not running - simulate success for demo
        setIsSubmitted(true);
        setFormData({ name: '', email: '', message: '' });
        toast.success('Message sent! (Demo mode - server not connected)');
        setTimeout(() => setIsSubmitted(false), 5000);
      } else {
        toast.error('Failed to send message. Please try again later.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    // Clear error when user starts typing
    if (errors[name as keyof FormErrors]) {
      setErrors((prev) => ({ ...prev, [name]: undefined }));
    }
  };

  return (
    <section id="contact" className="relative py-24 md:py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-[#22c55e]/5 rounded-full blur-[150px]" />
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
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 mb-6">
            <Mail className="w-4 h-4 text-[#22c55e]" />
            <span className="text-sm font-medium text-[#22c55e]">Get in Touch</span>
          </div>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6">
            Contact <span className="gradient-text">Support</span>
          </h2>
          <p className="text-lg text-white/60">
            Need help with ZXWY V2? Our community and support team are here to assist you.
          </p>
        </motion.div>

        {/* Stats */}
        <motion.div 
          className="grid grid-cols-2 gap-4 max-w-md mx-auto mb-12"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.2, duration: 0.6 }}
        >
          {stats.map((stat, index) => (
            <motion.div 
              key={stat.label}
              className="text-center p-5 rounded-xl glass-card"
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.3 + index * 0.1 }}
              whileHover={{ scale: 1.05 }}
            >
              <stat.icon className="w-6 h-6 text-[#22c55e] mx-auto mb-2" />
              <div className="text-2xl font-bold">{stat.value}</div>
              <div className="text-sm text-white/50">{stat.label}</div>
            </motion.div>
          ))}
        </motion.div>

        <div className="grid lg:grid-cols-2 gap-12 max-w-6xl mx-auto">
          {/* Left - Contact Methods */}
          <motion.div 
            className="space-y-6"
            initial={{ opacity: 0, x: -40 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, ease: [0.23, 1, 0.32, 1] }}
          >
            <h3 className="text-2xl font-semibold mb-6">Connect With Us</h3>
            
            {/* Contact Cards */}
            <div className="space-y-4">
              {contactMethods.map((method, index) => (
                <motion.a
                  key={method.name}
                  href={method.link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className={`
                    flex items-center gap-4 p-5 rounded-2xl border transition-all duration-300
                    ${method.color} ${method.hoverColor}
                  `}
                  initial={{ opacity: 0, x: -20 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.2 + index * 0.1 }}
                  whileHover={{ scale: 1.02, x: 5 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <div className="w-14 h-14 rounded-xl bg-black/20 flex items-center justify-center">
                    <method.icon className="w-7 h-7" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-lg">{method.name}</h4>
                    <p className="text-sm opacity-80">{method.description}</p>
                  </div>
                  <div className="w-10 h-10 rounded-lg bg-black/20 flex items-center justify-center">
                    <Send className="w-5 h-5" />
                  </div>
                </motion.a>
              ))}
            </div>

            {/* Info Box */}
            <div className="p-6 rounded-2xl glass-card">
              <h4 className="font-semibold mb-4 flex items-center gap-2">
                <Clock className="w-5 h-5 text-[#22c55e]" />
                Support Hours
              </h4>
              <div className="space-y-2 text-sm text-white/60">
                <p>Our community is active 24/7, but official support responses are typically provided during:</p>
                <div className="flex justify-between py-2 border-b border-white/10">
                  <span>Monday - Friday</span>
                  <span className="text-white">9:00 AM - 6:00 PM UTC</span>
                </div>
                <div className="flex justify-between py-2">
                  <span>Weekend</span>
                  <span className="text-white">Community Support Only</span>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Right - Contact Form */}
          <motion.div
            initial={{ opacity: 0, x: 40 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, delay: 0.1, ease: [0.23, 1, 0.32, 1] }}
          >
            <div className="glass-card p-8">
              <h3 className="text-2xl font-semibold mb-2">Send a Message</h3>
              <p className="text-white/50 mb-6">
                Fill out the form below and we'll get back to you as soon as possible.
              </p>

              {isSubmitted ? (
                <motion.div 
                  className="text-center py-12"
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                >
                  <div className="w-20 h-20 rounded-full bg-[#22c55e]/20 flex items-center justify-center mx-auto mb-6">
                    <CheckCircle2 className="w-10 h-10 text-[#22c55e]" />
                  </div>
                  <h4 className="text-2xl font-semibold mb-2">Message Sent!</h4>
                  <p className="text-white/60">
                    Thank you for reaching out. We'll respond within 24 hours.
                  </p>
                </motion.div>
              ) : (
                <form onSubmit={handleSubmit} className="space-y-5">
                  <div>
                    <label className="block text-sm font-medium mb-2 text-white/70">
                      Your Name
                    </label>
                    <input
                      type="text"
                      name="name"
                      placeholder="John Doe"
                      value={formData.name}
                      onChange={handleChange}
                      className={`
                        input-premium
                        ${errors.name ? 'border-red-500/50 focus:border-red-500' : ''}
                      `}
                    />
                    {errors.name && (
                      <p className="text-red-400 text-xs mt-1">{errors.name}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2 text-white/70">
                      Email Address
                    </label>
                    <input
                      type="email"
                      name="email"
                      placeholder="john@example.com"
                      value={formData.email}
                      onChange={handleChange}
                      className={`
                        input-premium
                        ${errors.email ? 'border-red-500/50 focus:border-red-500' : ''}
                      `}
                    />
                    {errors.email && (
                      <p className="text-red-400 text-xs mt-1">{errors.email}</p>
                    )}
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-2 text-white/70">
                      Message
                    </label>
                    <textarea
                      name="message"
                      placeholder="How can we help you?"
                      value={formData.message}
                      onChange={handleChange}
                      rows={5}
                      className={`
                        input-premium resize-none
                        ${errors.message ? 'border-red-500/50 focus:border-red-500' : ''}
                      `}
                    />
                    {errors.message && (
                      <p className="text-red-400 text-xs mt-1">{errors.message}</p>
                    )}
                  </div>

                  <motion.button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full btn-neon gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
                    whileHover={{ scale: isSubmitting ? 1 : 1.02 }}
                    whileTap={{ scale: isSubmitting ? 1 : 0.98 }}
                  >
                    {isSubmitting ? (
                      <>
                        <Loader2 className="w-5 h-5 animate-spin" />
                        Sending...
                      </>
                    ) : (
                      <>
                        <Send className="w-5 h-5" />
                        Send Message
                      </>
                    )}
                  </motion.button>

                  <p className="text-xs text-white/40 text-center">
                    By submitting this form, you agree to our privacy policy.
                  </p>
                </form>
              )}
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
