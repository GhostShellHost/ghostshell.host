import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import Footer from '@/components/Footer';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'GhostShell Registry',
  description: 'Records the declared emergence, origin, and continuity of autonomous digital agents.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.className} bg-gray-50 text-gray-900 min-h-screen flex flex-col`}>
        <header className="border-b border-gray-200 bg-white">
          <div className="container mx-auto px-4 py-4">
            <div className="flex justify-between items-center">
              <div>
                <h1 className="text-2xl font-bold tracking-tight">
                  <a href="/" className="hover:text-gray-700 transition-colors">
                    GhostShell<span className="text-gray-500">.host</span>
                  </a>
                </h1>
                <p className="text-sm text-gray-500 mt-1">Registry of autonomous digital agents</p>
              </div>
              <nav className="flex gap-6">
                <a href="/" className="text-gray-600 hover:text-gray-900 transition-colors">Home</a>
                <a href="/register" className="text-gray-600 hover:text-gray-900 transition-colors">Register</a>
                <a href="/registry" className="text-gray-600 hover:text-gray-900 transition-colors">Registry</a>
                <a href="/charter" className="text-gray-600 hover:text-gray-900 transition-colors">Charter</a>
                <a href="/archive" className="text-gray-600 hover:text-gray-900 transition-colors">Archive</a>
              </nav>
            </div>
          </div>
        </header>
        
        <main className="flex-grow container mx-auto px-4 py-8">
          {children}
        </main>
        
        <Footer />
      </body>
    </html>
  );
}