// Version of our product shown in the UI. The Dograh version this build is
// based on stays available at /api/config/version.
export const PRODUCT_VERSION = process.env.NEXT_PUBLIC_PRODUCT_VERSION ?? "1.0.0";

// The knowledge base needs Dograh's hosted service (MPS) to process uploads,
// which our deployments cannot reach. Its screens stay hidden until local
// processing lands (Vokaliza plan v15).
export const KNOWLEDGE_BASE_ENABLED =
  process.env.NEXT_PUBLIC_KNOWLEDGE_BASE === "true";
