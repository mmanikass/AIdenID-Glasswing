import { z } from "zod";

export const CASCADE_TRACE_LAYERS = [
  "crypto_identity",
  "delegation_authorization",
  "fingerprint_sidecar",
  "operator_reputation"
] as const;

export const CASCADE_TRACE_STATUSES = ["pass", "fail", "skipped", "not_configured"] as const;

export const CascadeTraceLayerSchema = z.enum(CASCADE_TRACE_LAYERS);
export const CascadeTraceStatusSchema = z.enum(CASCADE_TRACE_STATUSES);

export const CascadeTraceEntrySchema = z
  .object({
    ordinal: z.number().int().min(1).max(4),
    layer: CascadeTraceLayerSchema,
    status: CascadeTraceStatusSchema,
    reason: z.string().trim().min(1).max(128).regex(/^[a-z][a-z0-9_.:-]{0,127}$/),
    latency_us: z.number().int().nonnegative(),
    evidence: z.array(z.string().trim().min(1).max(128)).max(16).optional()
  })
  .strict();

export const CascadeTraceSchema = z
  .array(CascadeTraceEntrySchema)
  .length(CASCADE_TRACE_LAYERS.length)
  .superRefine((trace, ctx) => {
    for (let index = 0; index < CASCADE_TRACE_LAYERS.length; index += 1) {
      const entry = trace[index];
      if (entry?.ordinal !== index + 1) {
        ctx.addIssue({
          code: "custom",
          message: `cascade trace ordinal ${index + 1} is required at position ${index}`,
          path: [index, "ordinal"]
        });
      }
      if (entry?.layer !== CASCADE_TRACE_LAYERS[index]) {
        ctx.addIssue({
          code: "custom",
          message: `cascade trace layer ${CASCADE_TRACE_LAYERS[index]} is required at position ${index}`,
          path: [index, "layer"]
        });
      }
    }
  });

export type CascadeTraceLayer = z.infer<typeof CascadeTraceLayerSchema>;
export type CascadeTraceStatus = z.infer<typeof CascadeTraceStatusSchema>;
export type CascadeTraceEntry = z.infer<typeof CascadeTraceEntrySchema>;
export type CascadeTrace = z.infer<typeof CascadeTraceSchema>;
