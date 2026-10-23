// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup, waitFor } from '@testing-library/react';
import { OzApp } from '@oz/ui';

afterEach(() => cleanup());

describe('Desktop: アプリの起動', () => {
  it('起動直後はパスワード画面だけを出し、ノードは起動しない', async () => {
    render(<OzApp badge="Desktop Full Node" defaultTrackerUrl={null} />);
    await waitFor(() => expect(screen.getByLabelText('パスワード')).toBeTruthy());
    expect(screen.queryByText(/Peers:/)).toBeNull();
  });
});
