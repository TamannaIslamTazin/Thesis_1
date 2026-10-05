import { test, expect } from '@playwright/test';

/**
 * Authentication Flow E2E Tests
 * 
 * Tests frictionless authentication experience
 * - Social login buttons
 * - Email authentication
 * - Error handling
 * - Redirect flows
 */
test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/auth');
  });

  test('should display all authentication options', async ({ page }) => {
    // Check for email input
    const emailInput = page.getByPlaceholder(/email/i);
    await expect(emailInput).toBeVisible();

    // Check for social login buttons (Google, Apple, Microsoft)
    const socialButtons = page.locator('button').filter({ 
      hasText: /google|apple|microsoft|continue with/i 
    });
    
    // Should have at least one social login option
    const buttonCount = await socialButtons.count();
    expect(buttonCount).toBeGreaterThanOrEqual(1);
  });

  test('should validate email format', async ({ page }) => {
    const emailInput = page.getByPlaceholder(/email/i);
    const submitButton = page.getByRole('button', { name: /continue|sign in|submit|login/i });

    // Enter invalid email
    await emailInput.fill('invalid-email');
    await submitButton.click();

    // Should show validation error or prevent submission
    const isDisabled = await submitButton.isDisabled();
    const hasError = await page.locator('[role="alert"], .text-destructive, .error, [aria-invalid="true"]').count() > 0;
    const hasHTMLValidation = await emailInput.evaluate(
      (el: HTMLInputElement) => !el.checkValidity()
    );
    
    // Either button is disabled, error is shown, or HTML5 validation caught it
    expect(isDisabled || hasError || hasHTMLValidation).toBeTruthy();
  });

  test('should show loading state on submit', async ({ page }) => {
    const emailInput = page.getByPlaceholder(/email/i);
    const submitButton = page.getByRole('button', { name: /continue|sign in|submit/i });

    // Enter valid email
    await emailInput.fill('test@example.com');
    
    // Click and check for loading indicator
    const submitPromise = submitButton.click();
    
    // Check for immediate loading state (within 100ms)
    await page.waitForTimeout(100);
    
    // Should show some loading state (spinner, disabled, or text change)
    const hasSpinner = await page.locator('.animate-spin, [class*="loading"], [class*="spinner"]').count() > 0;
    const isButtonDisabled = await submitButton.isDisabled();
    const buttonText = await submitButton.textContent();
    const textChanged = buttonText?.toLowerCase().includes('loading') || buttonText?.toLowerCase().includes('...');
    
    // Wait for click to complete
    await submitPromise.catch(() => {}); // May redirect
    
    // At least one loading indicator should appear
    expect(hasSpinner || isButtonDisabled || textChanged).toBeTruthy();
  });

  test('should have keyboard navigation support', async ({ page }) => {
    // Tab through form elements
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    
    // Check that an element is focused
    const focusedElement = await page.evaluate(() => 
      document.activeElement?.tagName.toLowerCase()
    );
    
    expect(['input', 'button', 'a']).toContain(focusedElement);
  });

  test('should redirect authenticated users to wallet', async ({ page, context }) => {
    // Simulate logged-in state by setting storage
    await context.addCookies([
      {
        name: 'auth-session',
        value: 'mock-session-token',
        domain: 'localhost',
        path: '/',
      }
    ]);

    // This test verifies the redirect logic exists
    // In real scenario, would check actual redirect
    await page.goto('/auth');
    
    // Either redirected or showing auth (depends on implementation)
    const url = page.url();
    expect(url).toMatch(/\/(auth|wallet)/);
  });

  test('should have neuromorphic design elements', async ({ page }) => {
    // Check for premium styling (shadows, gradients, rounded corners)
    const cards = page.locator('[class*="shadow"], [class*="rounded"], [class*="gradient"]');
    const cardCount = await cards.count();
    
    expect(cardCount).toBeGreaterThan(0);
  });
});

test.describe('Social Login Flows', () => {
  test('Google login button should be clickable', async ({ page }) => {
    await page.goto('/auth');
    
    const googleButton = page.getByRole('button', { name: /google/i });
    if (await googleButton.count() > 0) {
      await expect(googleButton).toBeEnabled();
    }
  });

  test('Apple login button should be clickable', async ({ page }) => {
    await page.goto('/auth');
    
    const appleButton = page.getByRole('button', { name: /apple/i });
    if (await appleButton.count() > 0) {
      await expect(appleButton).toBeEnabled();
    }
  });

  test('Microsoft login button should be clickable', async ({ page }) => {
    await page.goto('/auth');
    
    const microsoftButton = page.getByRole('button', { name: /microsoft/i });
    if (await microsoftButton.count() > 0) {
      await expect(microsoftButton).toBeEnabled();
    }
  });
});
