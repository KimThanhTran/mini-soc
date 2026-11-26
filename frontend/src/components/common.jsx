import { useT } from '../i18n';

export function Severity({ level }) {
  const { t } = useT();
  return <span className={`badge sev-${level}`}>{t(`severity.${level}`)}</span>;
}

export const Technique = ({ id }) => (
  <a className="chip" href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`} target="_blank" rel="noreferrer noopener">{id}</a>
);

export function ErrorLine({ error }) {
  const { t } = useT();
  return error ? <p className="error" role="alert">{t('error.load', { message: error.message })}</p> : null;
}

/** 0 alerts: not shaded. Otherwise 25-70% of the alert colour (more would make the text unreadable), by share of the busiest technique. */
export const shade = (alerts, max) => (alerts > 0 && max > 0 ? Math.round(25 + 45 * (alerts / max)) : 0);
