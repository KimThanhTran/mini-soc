import { useEffect, useState } from 'react';
import { api } from '../api';
import { usePoll } from '../hooks';
import { useT } from '../i18n';
import { ErrorLine, Severity, Technique } from './common';

const COLUMNS = ['new', 'investigating', 'contained', 'closed'];
// mirrors incidents.TRANSITIONS on the server, which stays the authority
export const NEXT = { new: ['investigating', 'closed'], investigating: ['contained', 'closed'], contained: ['investigating', 'closed'], closed: ['investigating'] };

function Detail({ id, onChange, onClose }) {
  const { t, time } = useT();
  const { data: incident, error, refresh } = usePoll(() => api.incident(id), 4000);
  const [notes, setNotes] = useState(null);
  const [message, setMessage] = useState(null); // {text, ok}
  useEffect(() => { if (incident && notes === null) setNotes(incident.notes); }, [incident, notes]);

  const run = async (action) => {
    setMessage(null);
    try { await action(); await refresh(); onChange(); } catch (e) { setMessage({ text: e.status === 409 ? t('incident.conflict') : e.message, ok: false }); }
  };
  if (!incident) return <aside className="drawer card"><ErrorLine error={error} /></aside>;
  const types = [...new Set(incident.playbook.map((s) => s.type))];

  return (
    <aside className="drawer card" aria-label={`Incident ${incident.id}`}>
      <div className="row">
        <h2 className="mono">#{incident.id} {incident.entity}</h2>
        <button type="button" onClick={onClose} aria-label="Close panel">✕</button>
      </div>
      <div className="row left">
        <Severity level={incident.severity} />
        <span className="badge">{t(`status.${incident.status}`)}</span>
        {incident.types.map((ty) => <span key={ty} className="chip">{t(`type.${ty}`)}</span>)}
      </div>
      <div className="buttons">
        <span className="muted small">{t('incident.move')}</span>
        {NEXT[incident.status].map((to) => (
          <button key={to} type="button" className={to === 'closed' ? 'danger' : 'primary'} onClick={() => run(() => api.patch(id, { status: to }))}>
            {t(`status.${to}`)}
          </button>
        ))}
      </div>
      {message && <p className={message.ok ? 'good' : 'error'} role={message.ok ? 'status' : 'alert'}>{message.text}</p>}

      <h3>{t('incident.playbook')}</h3>
      {types.map((ty) => (
        <fieldset key={ty}>
          <legend>{t(`type.${ty}`)}</legend>
          {incident.playbook.map((s, i) => s.type === ty && (
            <label key={i} className="check">
              <input type="checkbox" checked={s.done} onChange={(e) => run(() => api.step(id, i, e.target.checked))} />
              <span className={s.done ? 'done' : ''}>{s.step}</span>
            </label>
          ))}
        </fieldset>
      ))}

      <h3>{t('incident.notes')}</h3>
      <textarea rows="3" value={notes ?? ''} maxLength={10000} onChange={(e) => setNotes(e.target.value)} />
      <button type="button" onClick={() => run(async () => { await api.patch(id, { notes }); setMessage({ text: t('incident.saved'), ok: true }); })}>{t('incident.save')}</button>

      <h3>{t('incident.timeline')}</h3>
      <ol className="timeline">
        {incident.timeline.slice().reverse().map((e, i) => (
          <li key={i} className={`kind-${e.kind}`}><span className="mono muted">{time(e.ts)}</span> {e.text}</li>
        ))}
      </ol>

      <h3>{t('incident.alertlist')} ({incident.alerts.length})</h3>
      <ul className="feed compact">
        {incident.alerts.slice().reverse().map((a) => (
          <li key={a.id}>
            <span className="mono muted">{time(a.ts)}</span>
            <span className="grow"><strong>{a.title}</strong><span className="muted small block">{a.summary}</span></span>
            {a.techniques.map((tid) => <Technique key={tid} id={tid} />)}
          </li>
        ))}
      </ul>
    </aside>
  );
}

export default function Incidents() {
  const { t } = useT();
  const { data, error, refresh } = usePoll(api.incidents);
  const [open, setOpen] = useState(null);
  return (
    <main className={`wide ${open ? 'with-drawer' : ''}`}>
      <ErrorLine error={error} />
      <div className="board">
        {COLUMNS.map((status) => {
          const items = (data || []).filter((i) => i.status === status);
          return (
            <section key={status} className="column" aria-label={t(`status.${status}`)}>
              <h2>{t(`status.${status}`)} <span className="muted">{items.length}</span></h2>
              {items.length === 0 && <p className="muted small">{t('board.empty')}</p>}
              {items.map((i) => (
                <button key={i.id} type="button" className={`card incident ${open === i.id ? 'selected' : ''}`} onClick={() => setOpen(i.id)}>
                  <span className="row left"><Severity level={i.severity} /><strong className="mono">{i.entity}</strong></span>
                  <span className="small">{i.types.map((ty) => t(`type.${ty}`)).join(' · ')}</span>
                  <span className="muted small">#{i.id} · {t('incident.alerts', { count: i.alert_count })}</span>
                </button>
              ))}
            </section>
          );
        })}
      </div>
      {open && <Detail key={open} id={open} onChange={refresh} onClose={() => setOpen(null)} />}
    </main>
  );
}
