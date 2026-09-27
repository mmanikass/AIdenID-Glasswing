import { Ban, RotateCcw } from "lucide-react";

export interface RevocationItem {
  readonly chainId: string;
  readonly epoch: number;
  readonly reason: string;
  readonly updatedAt: string;
}

export function RevocationCenter({ revocations }: { readonly revocations: readonly RevocationItem[] }) {
  return (
    <section className="panel revocation-panel" aria-labelledby="revocation-heading">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Revocation</p>
          <h2 id="revocation-heading">Epochs</h2>
        </div>
        <button className="icon-button danger" type="button" aria-label="Revoke chain">
          <Ban size={18} />
        </button>
      </div>
      <div className="revocation-list">
        {revocations.map((item) => (
          <div className="revocation-row" key={item.chainId}>
            <div>
              <strong>{item.chainId}</strong>
              <span>{item.reason}</span>
            </div>
            <div>
              <span>epoch {item.epoch}</span>
              <RotateCcw size={16} aria-hidden="true" />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
