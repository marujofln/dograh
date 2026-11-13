import { AuthShell } from "@/components/auth/AuthShell";
import { Button } from "@/components/ui/button";

// A dead end on purpose. Sending a failed sign-in back to the provider would
// loop: the provider still has a session and would return the same result.
const MESSAGES: Record<string, { title: string; body: string }> = {
  organization: {
    title: "No organization for this sign-in",
    body: "Your account must belong to exactly one organization for this session. Ask your administrator to add you to an organization, or sign in again and choose one.",
  },
  rejected: {
    title: "Sign-in was not accepted",
    body: "The identity provider signed you in, but the application did not accept the session. Ask your administrator to check the OpenID Connect configuration.",
  },
  state: {
    title: "Sign-in could not be completed",
    body: "The sign-in response did not match a request from this browser. It may have expired. Please try again.",
  },
  provider: {
    title: "Identity provider unavailable",
    body: "The identity provider could not be reached or returned an error. Please try again in a moment.",
  },
};

export const dynamic = "force-dynamic";

export default async function OidcErrorPage({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  const { reason } = await searchParams;
  const message = MESSAGES[reason ?? ""] ?? MESSAGES.provider;

  return (
    <AuthShell>
      <div className="space-y-4 text-center text-zinc-200">
        <h1 className="text-xl font-semibold">{message.title}</h1>
        <p className="text-sm text-muted-foreground">{message.body}</p>
        <div className="flex justify-center gap-3 pt-2">
          <Button asChild>
            <a href="/api/auth/oidc/login">Try again</a>
          </Button>
          <Button asChild variant="outline">
            <a href="/api/auth/oidc/logout">Sign out</a>
          </Button>
        </div>
      </div>
    </AuthShell>
  );
}
