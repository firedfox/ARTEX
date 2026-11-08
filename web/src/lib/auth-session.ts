/** A failed or ambiguous response must leave the browser's token available for retry. */
export async function revokeSession(token: string | null, request: typeof fetch = fetch): Promise<void> {
  const response = await request("/api/auth/logout", {
    method: "POST",
    credentials: "same-origin",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    signal: AbortSignal.timeout(15_000),
  });
  // A revoked or expired session cannot be used again and needs no further deletion.
  if (response.status === 401) return;
  if (response.status !== 200) throw new Error("The server did not confirm sign-out");
  const body: unknown = await response.json();
  if (!body || typeof body !== "object" || !("ok" in body) || body.ok !== true) {
    throw new Error("The server did not confirm sign-out");
  }
}
