import { useCallback, useEffect, useRef, useState } from 'react';

/** Calls `load` now and every `ms`, keeping the last good data on screen if a refresh fails. */
export function usePoll(load, ms = 3000) {
  const [state, setState] = useState({ data: null, error: null });
  const latest = useRef(load);
  latest.current = load;
  const refresh = useCallback(() => latest.current()
    .then((data) => setState({ data, error: null }))
    .catch((error) => setState((s) => ({ ...s, error }))), []);
  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, ms);
    return () => clearInterval(timer);
  }, [refresh, ms]);
  return { ...state, refresh };
}
