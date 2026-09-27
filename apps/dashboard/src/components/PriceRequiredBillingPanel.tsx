import { DollarSign } from "lucide-react";

import type { PriceRequiredIssuerBilling } from "../dashboardModel.js";

export function PriceRequiredBillingPanel({ rows }: { readonly rows: readonly PriceRequiredIssuerBilling[] }) {
  const total = rows.reduce((sum, row) => sum + row.estimatedGrossUsd, 0);
  return (
    <section className="panel price-billing-panel" aria-labelledby="price-billing-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Priced access</p>
          <h2 id="price-billing-heading">Issuer billing</h2>
        </div>
        <DollarSign size={20} aria-hidden="true" />
      </div>
      <div className="billing-total">
        <strong>${total.toFixed(4)}</strong>
        <span>estimated gross</span>
      </div>
      <div className="metric-list">
        {rows.map((row) => (
          <div className="metric-row" key={row.issuer}>
            <div>
              <strong className="mono">{row.issuer}</strong>
              <span>{row.decisionCount} price_required decisions</span>
            </div>
            <div>
              <span>${row.estimatedGrossUsd.toFixed(4)}</span>
              <span>{row.pricedDecisionCount} priced</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
