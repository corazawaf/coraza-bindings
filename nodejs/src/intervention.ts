// Copyright 2026 Juan Pablo Tosso <pablo@owasp.org> and Coraza Contributors
// SPDX-License-Identifier: Apache-2.0

import type { CorazaExports } from "./loader.js";
import { Memory } from "./memory.js";

/** A snapshotted WAF intervention (rule match that caused a disruptive action). */
export interface Intervention {
  /** HTTP status code to return to the client (e.g. 403 for deny). */
  readonly status: number;
  /** Action taken: "deny", "redirect", "pass", etc. */
  readonly action: string;
  /** Additional data, e.g. the redirect URL. Null when absent. */
  readonly data: string | null;
  /**
   * Release the native handle. Must be called exactly once after reading
   * status/action/data.
   */
  free(): void;
}

/** @internal */
export function readIntervention(
  exports: CorazaExports,
  memory: Memory,
  itHandle: number,
): Intervention {
  const status = exports.coraza_intervention_get_status(itHandle);

  const action = memory.readOut(64, (ptr, max) =>
    exports.coraza_intervention_get_action(itHandle, ptr, max),
  ) ?? "";

  const data = memory.readOut(1024, (ptr, max) =>
    exports.coraza_intervention_get_data(itHandle, ptr, max),
  );

  let freed = false;
  return {
    status,
    action,
    data,
    free() {
      if (!freed) {
        freed = true;
        exports.coraza_free_intervention(itHandle);
      }
    },
  };
}
