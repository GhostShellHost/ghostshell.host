import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { notFound } from 'next/navigation';

interface ArchivePageProps {
  params: Promise<{ slug?: string[] }>;
}

export default async function ArchivePage({ params }: ArchivePageProps) {
  const { slug = [] } = await params;
  
  // Determine the file path
  let filePath: string;
  if (slug.length === 0) {
    // Root archive path - show the original homepage
    filePath = join(process.cwd(), '..', '..', 'index.html');
  } else {
    // Handle nested paths like /archive/birth-certificate
    const path = slug.join('/');
    filePath = join(process.cwd(), '..', '..', path);
    
    // Check if it's a directory with index.html
    if (existsSync(join(filePath, 'index.html'))) {
      filePath = join(filePath, 'index.html');
    } else if (!filePath.endsWith('.html')) {
      filePath += '.html';
    }
  }
  
  // Check if file exists
  if (!existsSync(filePath)) {
    return notFound();
  }
  
  // Read the HTML file
  let html = readFileSync(filePath, 'utf-8');
  
  // Add archive banner at the top
  const banner = `
    <div style="
      background: #f0f0f0;
      border: 1px solid #ccc;
      border-radius: 4px;
      padding: 12px 16px;
      margin: 0 0 20px 0;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 14px;
      color: #333;
      text-align: center;
    ">
      <strong>Archived early GhostShell interface.</strong> Preserved for historical reference.
      <br>
      <a href="/" style="color: #666; text-decoration: underline;">Return to current GhostShell Registry</a>
    </div>
  `;
  
  // Insert banner after opening body tag
  html = html.replace(/<body[^>]*>/i, (match) => {
    return match + banner;
  });
  
  return (
    <div dangerouslySetInnerHTML={{ __html: html }} />
  );
}

export async function generateStaticParams() {
  // Generate static paths for known archive pages
  const archivePages = [
    { slug: [] }, // Root archive
    { slug: ['birth-certificate'] },
    { slug: ['policy'] },
    { slug: ['privacy'] },
    { slug: ['terms'] },
    { slug: ['v2'] },
    { slug: ['v2', 'birth-certificate'] },
  ];
  
  return archivePages;
}