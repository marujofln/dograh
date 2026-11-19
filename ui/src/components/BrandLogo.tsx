import { cn } from "@/lib/utils";

// Vokaliza wordmark (SVG with the text as outlines, from brand/ in the vokaliza
// repository), so it looks the same as on vokaliza.com without loading the font.
// Theme-aware by default: dark text on light surfaces, light text on dark.
// `inverse` forces the light version on an always-dark surface; `mark` shows
// only the symbol (e.g. the app sidebar header). Height comes from className.
export function BrandLogo({
  className,
  inverse = false,
  mark = false,
}: {
  className?: string;
  inverse?: boolean;
  mark?: boolean;
}) {
  if (mark) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img src="/vokaliza-mark.svg" alt="Vokaliza" className={cn("w-auto select-none", className)} />
    );
  }
  if (inverse) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img src="/vokaliza-logo-light.svg" alt="Vokaliza" className={cn("w-auto select-none", className)} />
    );
  }
  return (
    <>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/vokaliza-logo-dark.svg" alt="Vokaliza" className={cn("block w-auto select-none dark:hidden", className)} />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/vokaliza-logo-light.svg" alt="Vokaliza" className={cn("hidden w-auto select-none dark:block", className)} />
    </>
  );
}
