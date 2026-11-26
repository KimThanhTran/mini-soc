import { describe, expect, it } from 'vitest';
import { shade } from '../components/common';
import { NEXT } from '../components/Incidents';
import { dictionaries } from '../locales';
import { translate } from '../i18n';

describe('translate', () => {
  it('fills placeholders, falls back to English, then to the key', () => {
    expect(translate('vi', 'attackers.alerts', { count: 3 })).toBe('3 cảnh báo');
    expect(translate('vi', 'no.such.key')).toBe('no.such.key');
    expect(translate('xx', 'stat.alerts')).toBe('Alerts');
  });
  it('has every English key in Vietnamese and nothing extra', () => {
    expect(Object.keys(dictionaries.vi).sort()).toEqual(Object.keys(dictionaries.en).sort());
  });
});

describe('heat shading', () => {
  it('leaves quiet techniques unshaded and scales the rest', () => {
    expect(shade(0, 10)).toBe(0);
    expect(shade(10, 10)).toBe(70);
    expect(shade(1, 10)).toBeGreaterThan(25);
  });
});

describe('incident board', () => {
  it('only offers moves the server allows, and never to the same status', () => {
    for (const [from, moves] of Object.entries(NEXT)) expect(moves).not.toContain(from);
    expect(NEXT.new).not.toContain('contained');
  });
});
