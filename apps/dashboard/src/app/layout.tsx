import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "AIdenID Clearance Dashboard",
  description: "AIdenID operator dashboard"
};

export default function RootLayout({ children }: { readonly children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
