// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/react';
import Page from '../src/app/page';

afterEach(() => cleanup());

describe('Web: 起動', () => {
  it('起動直後はパスワード画面だけを出し、ラベルは Web', async () => {
    render(<Page />);
    await waitFor(() => expect(screen.getByLabelText('パスワード')).toBeTruthy());
    expect(screen.queryByText(/Peers:/)).toBeNull();
  });
});
