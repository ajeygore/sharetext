import { useState } from "react";
import type { SessionUser } from "../../shared/types";

/**
 * Up to two initials from whatever identity we have. Split on the separators
 * that show up in both display names and the local part of an address, so
 * "ajey.gore@example.com" gives AG rather than A.
 */
export function initialsFor(user: Pick<SessionUser, "name" | "email">): string {
  const source = (user.name || user.email || "").trim();
  const local = source.includes("@") ? source.split("@")[0] : source;
  return (
    local
      .split(/[\s._\-+]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]!.toUpperCase())
      .join("") || "?"
  );
}

/**
 * The user's Google picture, with an initials fallback.
 *
 * Two things go wrong with a bare <img src={user.picture}>: plenty of Google
 * accounts have no picture set at all, and the ones that do are served from a
 * rotating set of googleusercontent hosts that a request can still fail
 * against. Either way a raw img leaves a blank gap in the header, which reads
 * as a broken page rather than an account without a photo.
 */
export function Avatar({ user, size = 26 }: { user: SessionUser; size?: number }) {
  const [failed, setFailed] = useState(false);
  const initials = initialsFor(user);

  if (!user.picture || failed) {
    return (
      <span
        className="avatar avatar-initials"
        style={{ width: size, height: size, fontSize: size * 0.42 }}
        aria-hidden="true"
      >
        {initials}
      </span>
    );
  }

  return (
    <img
      className="avatar"
      src={user.picture}
      alt=""
      width={size}
      height={size}
      referrerPolicy="no-referrer"
      onError={() => setFailed(true)}
    />
  );
}
