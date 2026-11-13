// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from "react";

/** A value to copy, with a button; the clipboard may be refused (plain http), the value is still there to select. */
export function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="copy">
      <label>
        {label}
        <input readOnly value={value} onFocus={(e) => e.currentTarget.select()} />
      </label>
      <button
        type="button"
        onClick={() =>
          navigator.clipboard?.writeText(value).then(
            () => setCopied(true),
            () => setCopied(false),
          )
        }
      >
        {copied ? "Copied" : `Copy ${label.toLowerCase()}`}
      </button>
    </div>
  );
}
