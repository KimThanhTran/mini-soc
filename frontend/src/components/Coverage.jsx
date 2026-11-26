import { api } from '../api';
import { usePoll } from '../hooks';
import { useT } from '../i18n';
import { ErrorLine, shade } from './common';

export default function Coverage() {
  const { t } = useT();
  const { data, error } = usePoll(api.coverage, 5000);
  const max = data ? Math.max(0, ...data.tactics.flatMap((c) => c.techniques.map((x) => x.alerts))) : 0;

  return (
    <main className="wide">
      <h1>{t('coverage.title')}</h1>
      <p className="muted">{t('coverage.intro')}</p>
      <ErrorLine error={error} />
      <div className="matrix" role="table" aria-label={t('coverage.title')}>
        {data?.tactics.map((tactic) => (
          <div key={tactic.id} className="tactic" role="rowgroup">
            <h3 role="columnheader">{tactic.name}</h3>
            {tactic.techniques.length === 0 && <div className="tech empty muted small">{t('coverage.none')}</div>}
            {tactic.techniques.map((tech) => (
              <a key={tech.id} className="tech" role="cell" target="_blank" rel="noreferrer noopener"
                 href={`https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
                 title={tech.rules.join(', ')}
                 style={{ '--heat': `${shade(tech.alerts, max)}%` }}>
                <strong className="mono">{tech.id}</strong>
                <span className="small">{tech.name}</span>
                <span className="small muted">{tech.alerts} · {tech.rules.length} {tech.rules.length === 1 ? 'rule' : 'rules'}</span>
              </a>
            ))}
          </div>
        ))}
      </div>
      <p className="muted small">{t('coverage.legend')}: 0 <span className="legend" /> {max}</p>
      {data?.ml_alerts > 0 && <p className="muted small">{t('coverage.ml', { count: data.ml_alerts })}</p>}
    </main>
  );
}
