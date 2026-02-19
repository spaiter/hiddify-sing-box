import { test, expect, type Page } from '@playwright/test';

const BASE = 'http://127.0.0.1:19090';
const SECRET = 'test-secret-123';

test.describe('Panel Login', () => {
  test('shows login overlay when no token', async ({ page }) => {
    await page.goto(BASE + '/panel/');
    await page.evaluate(() => localStorage.removeItem('sb-panel-token'));
    await page.reload();

    const overlay = page.locator('#loginOverlay');
    await expect(overlay).toBeVisible();

    const nav = page.locator('#tabNav');
    await expect(nav).toBeHidden();
  });

  test('rejects invalid secret', async ({ page }) => {
    await page.goto(BASE + '/panel/');
    await page.evaluate(() => localStorage.removeItem('sb-panel-token'));
    await page.reload();

    await page.fill('#loginSecret', 'wrong-secret');
    await page.click('.login-box .btn');

    const error = page.locator('#loginError');
    await expect(error).toBeVisible();
    await expect(error).toHaveText('Invalid secret');
  });

  test('accepts valid secret and shows dashboard', async ({ page }) => {
    await page.goto(BASE + '/panel/');
    await page.evaluate(() => localStorage.removeItem('sb-panel-token'));
    await page.reload();

    await page.fill('#loginSecret', SECRET);
    await page.click('.login-box .btn');

    await expect(page.locator('#loginOverlay')).toBeHidden();
    await expect(page.locator('#tabNav')).toBeVisible();
    await expect(page.locator('#dashboard')).toHaveClass(/active/);
  });
});

async function login(page: Page) {
  await page.goto(BASE + '/panel/');
  await page.evaluate((s: string) => localStorage.setItem('sb-panel-token', s), SECRET);
  await page.reload();
  await expect(page.locator('#tabNav')).toBeVisible();
}

test.describe('Dashboard Tab', () => {
  test('shows version info', async ({ page }) => {
    await login(page);

    const version = page.locator('#versionDisplay');
    await expect(version).not.toHaveText('-');
    await expect(version).toContainText('sing-box');
  });

  test('shows traffic stats', async ({ page }) => {
    await login(page);

    await expect(page.locator('#uploadSpeed')).toBeVisible();
    await expect(page.locator('#downloadSpeed')).toBeVisible();
    await expect(page.locator('#memoryUsage')).toBeVisible();
  });
});

test.describe('Config Tab', () => {
  test('loads and displays JSON config', async ({ page }) => {
    await login(page);

    await page.click('nav.tabs button[data-tab="config"]');
    await expect(page.locator('#config')).toHaveClass(/active/);

    const configJson = page.locator('#configJson');
    await expect(configJson).not.toHaveText('Loading...');

    const text = (await configJson.textContent()) || '';
    const parsed = JSON.parse(text);
    expect(parsed).toHaveProperty('inbounds');
    expect(parsed).toHaveProperty('outbounds');
  });

  test('copy button exists', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="config"]');

    const copyBtn = page.locator('button', { hasText: 'Copy JSON' });
    await expect(copyBtn).toBeVisible();
  });
});

test.describe('Inbounds Tab', () => {
  test('lists existing inbounds', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="inbounds"]');
    await expect(page.locator('#inbounds')).toHaveClass(/active/);

    const rows = page.locator('#inboundsBody tr');
    await expect(rows).toHaveCount(2);

    await expect(page.locator('#inboundsBody')).toContainText('ss-in');
    await expect(page.locator('#inboundsBody')).toContainText('shadowsocks');
    await expect(page.locator('#inboundsBody')).toContainText('vmess-in');
    await expect(page.locator('#inboundsBody')).toContainText('vmess');
  });

  test('edit inbound opens dialog with JSON', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="inbounds"]');

    await page.locator('#inboundsBody button', { hasText: 'Edit' }).first().click();

    const dialog = page.locator('#inboundDialog');
    await expect(dialog).toBeVisible();

    const json = await page.locator('#inboundJson').inputValue();
    expect(json.length).toBeGreaterThan(10);
    const parsed = JSON.parse(json);
    expect(parsed.type).toBe('shadowsocks');

    await page.locator('#inboundDialog button', { hasText: 'Cancel' }).click();
  });

  test('add inbound dialog opens empty', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="inbounds"]');

    await page.locator('#inbounds button', { hasText: 'Add Inbound' }).click();
    const dialog = page.locator('#inboundDialog');
    await expect(dialog).toBeVisible();

    const title = page.locator('#inboundDialogTitle');
    await expect(title).toHaveText('Add Inbound');

    const json = await page.locator('#inboundJson').inputValue();
    expect(json).toBe('');

    await page.locator('#inboundDialog button', { hasText: 'Cancel' }).click();
  });
});

test.describe('Endpoints Tab', () => {
  test('lists existing endpoints', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="endpoints"]');
    await expect(page.locator('#endpoints')).toHaveClass(/active/);

    const rows = page.locator('#endpointsBody tr');
    await expect(rows).toHaveCount(1);

    await expect(page.locator('#endpointsBody')).toContainText('awg-ep');
    await expect(page.locator('#endpointsBody')).toContainText('awg');
  });

  test('edit endpoint opens dialog with JSON', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="endpoints"]');

    await page.locator('#endpointsBody button', { hasText: 'Edit' }).first().click();

    const dialog = page.locator('#endpointDialog');
    await expect(dialog).toBeVisible();

    const json = await page.locator('#endpointJson').inputValue();
    expect(json.length).toBeGreaterThan(10);
    const parsed = JSON.parse(json);
    expect(parsed.type).toBe('awg');

    await page.locator('#endpointDialog button', { hasText: 'Cancel' }).click();
  });

  test('add endpoint dialog opens empty', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="endpoints"]');

    await page.locator('#endpoints button', { hasText: 'Add Endpoint' }).click();
    const dialog = page.locator('#endpointDialog');
    await expect(dialog).toBeVisible();

    const title = page.locator('#endpointDialogTitle');
    await expect(title).toHaveText('Add Endpoint');

    const json = await page.locator('#endpointJson').inputValue();
    expect(json).toBe('');

    await page.locator('#endpointDialog button', { hasText: 'Cancel' }).click();
  });
});

test.describe('Users Tab', () => {
  test('shows inbound selector', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="users"]');
    await expect(page.locator('#users')).toHaveClass(/active/);

    const select = page.locator('#userInboundSelect');
    await expect(select).toBeVisible();

    const options = select.locator('option');
    await expect(options).toHaveCount(3);
  });

  test('selecting inbound shows users', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="users"]');

    await page.selectOption('#userInboundSelect', 'ss-in');

    const tbody = page.locator('#usersBody');
    await expect(tbody).toContainText('alice');

    await expect(page.locator('#addUserBtn')).toBeVisible();
  });

  test('selecting vmess inbound shows users', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="users"]');

    await page.selectOption('#userInboundSelect', 'vmess-in');

    const tbody = page.locator('#usersBody');
    await expect(tbody).toContainText('bob');
  });

  test('add user shows dynamic form for shadowsocks', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="users"]');
    await page.selectOption('#userInboundSelect', 'ss-in');

    await page.click('#addUserBtn');

    const dialog = page.locator('#userDialog');
    await expect(dialog).toBeVisible();

    await expect(dialog.locator('[data-key="name"]')).toBeVisible();
    await expect(dialog.locator('[data-key="password"]')).toBeVisible();

    await dialog.locator('button', { hasText: 'Cancel' }).click();
  });

  test('add user shows dynamic form for vmess with UUID generate', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="users"]');
    await page.selectOption('#userInboundSelect', 'vmess-in');

    await page.click('#addUserBtn');

    const dialog = page.locator('#userDialog');
    await expect(dialog).toBeVisible();

    await expect(dialog.locator('[data-key="name"]')).toBeVisible();
    await expect(dialog.locator('[data-key="uuid"]')).toBeVisible();

    const genBtn = dialog.locator('button', { hasText: 'Generate' });
    await expect(genBtn).toBeVisible();

    await genBtn.click();
    const uuid = await dialog.locator('[data-key="uuid"]').inputValue();
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

    await dialog.locator('button', { hasText: 'Cancel' }).click();
  });

  test('can add and delete a user', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="users"]');
    await page.selectOption('#userInboundSelect', 'ss-in');

    await page.click('#addUserBtn');
    const dialog = page.locator('#userDialog');
    await dialog.locator('[data-key="name"]').fill('test-user-pw');
    await dialog.locator('[data-key="password"]').fill('test-pass-123');
    await dialog.locator('button', { hasText: 'Add' }).click();

    await expect(dialog).toBeHidden();

    await expect(page.locator('#usersBody')).toContainText('test-user-pw');

    const row = page.locator('#usersBody tr', { hasText: 'test-user-pw' });
    await row.locator('button', { hasText: 'Delete' }).click();

    const confirmDlg = page.locator('#confirmDialog');
    await expect(confirmDlg).toBeVisible();
    await confirmDlg.locator('#confirmOk').click();

    await expect(page.locator('#usersBody')).not.toContainText('test-user-pw');
  });
});

test.describe('Connections Tab', () => {
  test('shows connections table', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="connections"]');
    await expect(page.locator('#connections')).toHaveClass(/active/);

    await expect(page.locator('#connCount')).toBeVisible();

    await expect(page.locator('button', { hasText: 'Close All' })).toBeVisible();

    await expect(page.locator('#connections th', { hasText: 'Network' })).toBeVisible();
    await expect(page.locator('#connections th', { hasText: 'Source' })).toBeVisible();
    await expect(page.locator('#connections th', { hasText: 'Destination' })).toBeVisible();
  });
});

test.describe('Stats Tab', () => {
  test('shows stats table', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="stats"]');
    await expect(page.locator('#stats')).toHaveClass(/active/);

    await expect(page.locator('#stats th', { hasText: 'User' })).toBeVisible();
    await expect(page.locator('#stats th', { hasText: 'Upload' })).toBeVisible();
    await expect(page.locator('#stats th', { hasText: 'Download' })).toBeVisible();
  });

  test('shows empty state or user rows', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="stats"]');

    const body = page.locator('#statsBody');
    await expect(body).toBeVisible();
    // Either shows "No user stats yet" or actual user rows
    const text = await body.textContent();
    expect(text!.length).toBeGreaterThan(0);
  });

  test('detail dialog shows daily breakdown and resources tables', async ({ page }) => {
    await login(page);
    await page.click('nav.tabs button[data-tab="stats"]');

    // Mock the APIs so the dialog can open even without real data
    await page.evaluate(() => {
      const origFetch = window.fetch;
      (window as any)._origFetch = origFetch;
      window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === 'string' ? input : input.toString();
        if (url.includes('/stats/users/') && url.includes('/resources')) {
          return new Response(JSON.stringify([]), { headers: { 'content-type': 'application/json' } });
        }
        if (url.includes('/stats/users/') && !url.includes('/resources')) {
          return new Response(JSON.stringify({ user: 'test', daily: [] }), { headers: { 'content-type': 'application/json' } });
        }
        return origFetch(input, init);
      };
    });

    // Call showUserDetail directly
    await page.evaluate(() => (window as any).showUserDetail('test'));

    const dialog = page.locator('#userStatsDialog');
    await expect(dialog).toBeVisible();

    // Verify daily breakdown table headers exist
    await expect(dialog.locator('th', { hasText: 'Date' })).toBeVisible();

    // Verify resources table headers exist
    await expect(dialog.locator('th', { hasText: 'Resource' })).toBeVisible();
    await expect(dialog.locator('#userStatsResources')).toBeVisible();

    // Restore fetch
    await page.evaluate(() => { window.fetch = (window as any)._origFetch; });
  });
});

test.describe('Tab Navigation', () => {
  test('all tabs are clickable and switch content', async ({ page }) => {
    await login(page);

    const tabs = ['dashboard', 'config', 'inbounds', 'endpoints', 'users', 'connections', 'stats'];
    for (const tab of tabs) {
      await page.click(`nav.tabs button[data-tab="${tab}"]`);
      await expect(page.locator(`#${tab}`)).toHaveClass(/active/);

      await expect(page.locator(`nav.tabs button[data-tab="${tab}"]`)).toHaveClass(/active/);

      for (const other of tabs) {
        if (other !== tab) {
          await expect(page.locator(`#${other}`)).not.toHaveClass(/active/);
        }
      }
    }
  });
});

test.describe('Auth Persistence', () => {
  test('token persists across page reload', async ({ page }) => {
    await login(page);

    await page.reload();

    await expect(page.locator('#loginOverlay')).toBeHidden();
    await expect(page.locator('#tabNav')).toBeVisible();
  });
});
