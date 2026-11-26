import { useEffect, useState } from 'react';
import { api, getToken, setToken } from './api';
import { LANGUAGES, useT } from './i18n';
import { ThemeSwitch } from './theme';
import Coverage from './components/Coverage';
import Incidents from './components/Incidents';
import Overview from './components/Overview';

const PAGES = { overview: Overview, incidents: Incidents, coverage: Coverage };
const pageFromHash = () => (window.location.hash.slice(1) in PAGES ? window.location.hash.slice(1) : 'overview');

function Login({ onDone }) {
  const { t } = useT();
  const [token, setValue] = useState('');
  const [bad, setBad] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    try {
      await api.check(token);
      setToken(token);
      onDone();
    } catch {
      setBad(true);
    }
  };
  return (
    <main className="narrow">
      <form className="card" onSubmit={submit}>
        <h1>{t('login.title')}</h1>
        <label>
          {t('login.token')}
          <input type="password" value={token} onChange={(e) => { setValue(e.target.value); setBad(false); }} autoFocus required />
        </label>
        {bad && <p className="error" role="alert">{t('login.bad')}</p>}
        <p className="muted small">{t('login.hint')}</p>
        <button className="primary" type="submit">{t('login.submit')}</button>
      </form>
    </main>
  );
}

export default function App() {
  const { t, lang, setLang } = useT();
  const [signedIn, setSignedIn] = useState(() => Boolean(getToken()));
  const [page, setPage] = useState(pageFromHash);

  useEffect(() => {
    const onHash = () => setPage(pageFromHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);
  // a rejected token (changed or expired) sends the analyst back to the sign-in form
  useEffect(() => {
    const onDenied = () => { setToken(''); setSignedIn(false); };
    window.addEventListener('minisoc:unauthorized', onDenied);
    return () => window.removeEventListener('minisoc:unauthorized', onDenied);
  }, []);

  const Page = PAGES[page];
  return (
    <>
      <header className="top">
        <a className="brand" href="#overview">🛡️ mini-soc</a>
        {signedIn && (
          <nav>
            {Object.keys(PAGES).map((key) => (
              <a key={key} href={`#${key}`} className={key === page ? 'active' : ''}>{t(`nav.${key}`)}</a>
            ))}
          </nav>
        )}
        <div className="who">
          <select aria-label="Language" value={lang} onChange={(e) => setLang(e.target.value)}>
            {LANGUAGES.map(([code, name]) => <option key={code} value={code}>{name}</option>)}
          </select>
          <ThemeSwitch />
          {signedIn && <button type="button" onClick={() => { setToken(''); setSignedIn(false); }}>{t('logout')}</button>}
        </div>
      </header>
      {signedIn ? <Page /> : <Login onDone={() => setSignedIn(true)} />}
    </>
  );
}
