import { redirect } from "next/navigation";

import { getAuthProvider, getSignupEnabled } from "@/lib/auth/config";
import { OIDC_LOGIN_PATH } from "@/lib/auth/oidc";

import { LoginForm } from "./LoginForm";

// Resolve the backend health check before rendering so the "Sign up" link is
// correct on first paint — no client-side fetch, no flicker on locked-down
// installs. force-dynamic keeps the page off the build-time prerender, which
// would bake in the flag's build-environment value.
export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ idp?: string }>;
}) {
  // With an OpenID Connect provider there is no password to type here.
  if ((await getAuthProvider()) === "oidc") {
    // /auth/login?idp=<alias> is the per-customer sign-in address.
    const { idp } = await searchParams;
    redirect(
      typeof idp === "string"
        ? `${OIDC_LOGIN_PATH}?idp=${encodeURIComponent(idp)}`
        : OIDC_LOGIN_PATH,
    );
  }
  const signupEnabled = await getSignupEnabled();
  return <LoginForm signupEnabled={signupEnabled} />;
}
