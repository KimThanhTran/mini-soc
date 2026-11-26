import { api } from '../api';
import { usePoll } from '../hooks';
import { useT } from '../i18n';
import { ErrorLine, Severity, Technique } from './common';

const ML_RULE = 'ml-isolation-forest';

function Tile({ label, value, tone }) {
  return (
    <div className={`card tile ${tone || ''}`}>
      <div className="muted small">{label}</div>
      <div className="big">{value ?? '–'}</div>
    </div>
  );
}

function Bars({ values }) {
  const max = Math.max(1, ...values);
  return (
    <svg viewBox="0 0 240 60" className="bars" role="img" aria-label={values.join(', ')}>
      {values.map((v, i) => {
        const h = (v / max) * 52;
        return <rect key={i} x={i * 20 + 3} y={58 - h} width="14" height={Math.max(h, v ? 2 : 0.5)} rx="2" />;
      })}
    </svg>
  );
}

export default function Overview() {
  const { t, time } = useT();
  const stats = usePoll(api.stats);
  const alerts = usePoll(api.alerts);
  const s = stats.data;
  const open = s ? Object.entries(s.incidents).filter(([k]) => k !== 'closed').reduce((n, [, v]) => n + v, 0) : null;
  const mlAlerts = alerts.data ? alerts.data.filter((a) => a.rule_id === ML_RULE).length : null;

  return (
    <main>
      <p className="muted">{t('app.subtitle')}</p>
      <ErrorLine error={stats.error || alerts.error} />
      <div className="tiles">
        <Tile label={t('stat.events')} value={s?.events.toLocaleString()} />
        <Tile label={t('stat.alerts')} value={s?.alerts.toLocaleString()} tone="warn" />
        <Tile label={t('stat.open')} value={open} tone="bad" />
        <Tile label={t('stat.ml')} value={mlAlerts} />
      </div>
      <div className="grid2">
        <section className="card">
          <h2>{t('feed.title')}</h2>
          {alerts.data?.length === 0 && <p className="muted">{t('feed.empty')}</p>}
          <ul className="feed">
            {alerts.data?.map((a) => (
              <li key={a.id}>
                <span className="mono muted">{time(a.ts)}</span>
                <Severity level={a.severity} />
                <span className="grow">
                  <strong>{a.title}</strong>
                  <span className="muted small block">{a.src_ip || a.user}{a.rule_id === ML_RULE ? '' : ` · ${a.rule_id}`}</span>
                </span>
                {a.rule_id === ML_RULE ? <span className="chip ml">{t('feed.ml')}</span> : a.techniques.map((id) => <Technique key={id} id={id} />)}
              </li>
            ))}
          </ul>
        </section>
        <div>
          <section className="card">
            <h2>{t('chart.title')}</h2>
            <Bars values={s?.alerts_per_5min ?? Array(12).fill(0)} />
          </section>
          <section className="card">
            <h2>{t('attackers.title')}</h2>
            {s?.top_attackers.length === 0 && <p className="muted">{t('attackers.empty')}</p>}
            <table>
              <tbody>
                {s?.top_attackers.map((a) => (
                  <tr key={a.ip}>
                    <td className="mono">{a.ip}</td>
                    <td className="muted">{a.country || ''}</td>
                    <td className="right">{t('attackers.alerts', { count: a.alerts })}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      </div>
    </main>
  );
}
