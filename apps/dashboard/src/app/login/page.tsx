export const dynamic = "force-dynamic";

export default function LoginPage() {
  return (
    <main
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        background: "#0a0a0b",
        color: "#f4f5f4",
        fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif",
        padding: 24,
      }}
    >
      <div
        style={{
          maxWidth: 420,
          width: "100%",
          padding: 32,
          textAlign: "center",
          border: "1px solid rgba(255,255,255,.1)",
          borderRadius: 16,
          background: "rgba(255,255,255,.03)",
        }}
      >
        <h1 style={{ fontSize: 24, margin: "0 0 8px" }}>AIdenID Clearance</h1>
        <p style={{ color: "#9aa0a0", margin: "0 0 24px", fontSize: 15 }}>
          Sign in to your clearance dashboard.
        </p>
        <a
          href="/auth/start"
          style={{
            display: "inline-block",
            background: "#1fdc4d",
            color: "#06210f",
            fontWeight: 600,
            textDecoration: "none",
            padding: "12px 24px",
            borderRadius: 999,
          }}
        >
          Continue with Google or GitHub
        </a>
        <p style={{ color: "#6b7070", margin: "20px 0 0", fontSize: 12 }}>
          Uses your Sentinelayer account. New here? Signing in creates your
          access.
        </p>
      </div>
    </main>
  );
}
