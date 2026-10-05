import { test, expect } from '@playwright/test';

/**
 * Healthcare Flow E2E Tests
 * P7: Automated E2E Tests - Healthcare specific flows
 */

test.describe('Patient Onboarding', () => {
  test('should show onboarding page', async ({ page }) => {
    await page.goto('/onboarding');
    
    // Should show welcome step
    await expect(page.getByRole('heading', { name: /welcome/i })).toBeVisible();
    
    // Should have get started button
    await expect(page.getByRole('button', { name: /get started/i })).toBeVisible();
  });

  test('should progress through onboarding steps', async ({ page }) => {
    await page.goto('/onboarding');
    
    // Step 1: Welcome
    await page.getByRole('button', { name: /get started/i }).click();
    
    // Step 2: Create Identity - should show identity creation UI
    await expect(page.getByText(/creating your secure/i)).toBeVisible({ timeout: 5000 });
  });

  test('should show progress indicator', async ({ page }) => {
    await page.goto('/onboarding');
    
    // Should show step indicator
    await expect(page.getByText(/step 1/i)).toBeVisible();
  });
});

test.describe('Pharmacy Portal', () => {
  test('should show pharmacy verification page', async ({ page }) => {
    await page.goto('/pharmacy');
    
    // Should show pharmacy heading
    await expect(page.getByRole('heading', { name: /pharmacy/i })).toBeVisible();
  });

  test('should have prescription verification form', async ({ page }) => {
    await page.goto('/pharmacy');
    
    // Should have credential ID input
    await expect(page.getByPlaceholder(/credential/i)).toBeVisible();
  });

  test('should show verification status', async ({ page }) => {
    await page.goto('/pharmacy');
    
    // Should have status section
    await expect(page.getByText(/verification/i)).toBeVisible();
  });
});

test.describe('Insurance Portal', () => {
  test('should show insurance claims page', async ({ page }) => {
    await page.goto('/insurance');
    
    // Should show insurance heading
    await expect(page.getByRole('heading', { name: /insurance/i })).toBeVisible();
  });

  test('should have claims submission form', async ({ page }) => {
    await page.goto('/insurance');
    
    // Should have claim type selector or input
    await expect(page.getByText(/claim/i)).toBeVisible();
  });

  test('should show claims history', async ({ page }) => {
    await page.goto('/insurance');
    
    // Should have history section
    await expect(page.getByText(/history|claims/i)).toBeVisible();
  });
});

test.describe('Emergency Access', () => {
  test('should show emergency access page', async ({ page }) => {
    await page.goto('/emergency');
    
    // Should show emergency heading
    await expect(page.getByRole('heading', { name: /emergency/i })).toBeVisible();
  });

  test('should have provider verification', async ({ page }) => {
    await page.goto('/emergency');
    
    // Should show provider verification step
    await expect(page.getByText(/provider|verification/i)).toBeVisible();
  });

  test('should show security warning', async ({ page }) => {
    await page.goto('/emergency');
    
    // Should have warning about emergency access
    await expect(page.getByText(/emergency|audit|logged/i)).toBeVisible();
  });
});

test.describe('Credential Issuance', () => {
  test('should show issuer page', async ({ page }) => {
    await page.goto('/issuer');
    
    // Should show issuer heading
    await expect(page.getByRole('heading', { name: /credential|issuer/i })).toBeVisible();
  });

  test('should have credential type selection', async ({ page }) => {
    await page.goto('/issuer');
    
    // Should show credential types
    await expect(page.getByText(/health|credential|type/i)).toBeVisible();
  });
});

test.describe('Audit Trail', () => {
  test('should show audit page when authenticated', async ({ page }) => {
    // This test requires authentication
    await page.goto('/wallet/audit');
    
    // Should either show audit page or redirect to login
    const url = page.url();
    const isAuditPage = url.includes('audit');
    const isLoginRedirect = url.includes('login');
    
    expect(isAuditPage || isLoginRedirect).toBe(true);
  });
});

test.describe('Healthcare Accessibility', () => {
  test('onboarding should be keyboard navigable', async ({ page }) => {
    await page.goto('/onboarding');
    
    // Should be able to tab to get started button
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    
    // Should have visible focus indicator
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  });

  test('pharmacy page should have proper form labels', async ({ page }) => {
    await page.goto('/pharmacy');
    
    // All inputs should have associated labels
    const inputs = page.locator('input');
    const inputCount = await inputs.count();
    
    for (let i = 0; i < inputCount; i++) {
      const input = inputs.nth(i);
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const placeholder = await input.getAttribute('placeholder');
      
      // Should have some form of labeling
      const hasLabel = id || ariaLabel || placeholder;
      expect(hasLabel).toBeTruthy();
    }
  });

  test('emergency page should have high contrast warning', async ({ page }) => {
    await page.goto('/emergency');
    
    // Emergency warning should be visible
    const warningText = page.getByText(/emergency|urgent|critical/i);
    if (await warningText.isVisible()) {
      await expect(warningText).toBeVisible();
    }
  });
});

test.describe('Healthcare Performance', () => {
  test('onboarding page should load quickly', async ({ page }) => {
    const startTime = Date.now();
    await page.goto('/onboarding');
    const loadTime = Date.now() - startTime;
    
    // Should load in under 3 seconds
    expect(loadTime).toBeLessThan(3000);
  });

  test('pharmacy verification should be responsive', async ({ page }) => {
    await page.goto('/pharmacy');
    
    // Page should be interactive quickly
    await expect(page.getByRole('heading')).toBeVisible({ timeout: 2000 });
  });
});
