"use client";

import { useEffect, useRef, useState } from "react";

import { PageShell } from "@/components/layout/PageShell";

// Usage statement and billing come from our own control-plane service
// (vokaliza repository, control-plane/ui), shown here in a frame so they keep
// this app's sidebar, header and theme. The frame tells us its content height
// and asks for the theme; see control-plane/ui/src/lib/theme.ts.
const BILLING_URL = process.env.NEXT_PUBLIC_BILLING_URL ?? "";

const MESSAGE_READY = "vokaliza:ready";
const MESSAGE_THEME = "vokaliza:theme";
const MESSAGE_HEIGHT = "vokaliza:height";

function currentTheme(): "light" | "dark" {
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

export default function StatementPage() {
  const frameRef = useRef<HTMLIFrameElement>(null);
  const [src, setSrc] = useState<string | null>(null);
  const [height, setHeight] = useState<number | null>(null);

  const origin = (() => {
    try {
      return new URL(BILLING_URL).origin;
    } catch {
      return "";
    }
  })();

  useEffect(() => {
    if (!origin) return;
    // The theme in the first URL avoids a flash before the frame asks for it.
    const url = new URL(BILLING_URL);
    url.searchParams.set("theme", currentTheme());
    setSrc(url.toString());

    const sendTheme = () =>
      frameRef.current?.contentWindow?.postMessage(
        { type: MESSAGE_THEME, theme: currentTheme() },
        origin,
      );

    const onMessage = (event: MessageEvent) => {
      if (event.origin !== origin || event.source !== frameRef.current?.contentWindow) return;
      const data = (event.data ?? {}) as { type?: string; height?: unknown };
      if (data.type === MESSAGE_READY) {
        sendTheme();
      } else if (data.type === MESSAGE_HEIGHT && typeof data.height === "number" && data.height > 0) {
        setHeight(Math.ceil(data.height));
      }
    };
    window.addEventListener("message", onMessage);

    // The theme toggle only flips the class on <html>; follow it.
    const observer = new MutationObserver(sendTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });

    return () => {
      window.removeEventListener("message", onMessage);
      observer.disconnect();
    };
  }, [origin]);

  if (!origin) return null;

  return (
    <PageShell className="py-6">
      {src && (
        <iframe
          ref={frameRef}
          src={src}
          title="Billing"
          className="block w-full border-0 bg-transparent"
          // Until the frame reports its height, fill the visible area.
          style={{ height: height ?? "calc(100vh - 8rem)" }}
        />
      )}
    </PageShell>
  );
}
