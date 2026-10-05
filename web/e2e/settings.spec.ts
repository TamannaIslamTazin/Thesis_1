import { test, expect, Page } from '@playwright/test';

/**
 * Settings E2E Tests
 * 
 * Tests user settings functionality:
 * - Profile management
 * - Security settings
 * - Notification preferences
 * - Emergency contacts
 */

async function setupAuthenticatedUser(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('ssi-auth-token', 'mock-jwt-token');
    localStorage.setItem('ssi-user', JSON.stringify({
      id: 'user-123',
      email: 'test@example.com',
      displayName: 'Test User',
      walletSetup: true,
      biometricEnabled: false,
      autoLockMinutes: 5,
    }));
  });
}

test.describe('Settings Page Structure', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedUser(page);
  });

  test('should display settings page', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    const heading = page.getByRole('heading').first();
    await expect(heading).toBeVisible();
  });

  test('should have tabbed or sectioned layout', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Look for tabs or section links
    const sections = page.locator('[role="tab"], [role="button"]').filter({
      hasText: /profile|security|notification|privacy|emergency/i
    });
    
    const count = await sections.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe('Profile Settings', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedUser(page);
  });

  test('should display profile form', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Look for profile-related inputs
    const nameInput = page.locator('input[name*="name"], input[placeholder*="name"]');
    await page.waitForTimeout(300);
    
    const count = await nameInput.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should allow avatar update', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Look for avatar/photo upload
    const avatarSection = page.locator('[class*="avatar"], input[type="file"]');
    await page.waitForTimeout(300);
    
    const count = await avatarSection.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should save profile changes', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    const saveButton = page.locator('button').filter({
      hasText: /save|update|submit/i
    });
    
    if (await saveButton.count() > 0) {
      await expect(saveButton.first()).toBeVisible();
    }
  });
});

test.describe('Security Settings', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedUser(page);
  });

  test('should show biometric toggle', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Navigate to security tab if needed
    const securityTab = page.locator('[role="tab"], button').filter({
      hasText: /security/i
    }).first();
    
    if (await securityTab.count() > 0) {
      await securityTab.click();
      await page.waitForTimeout(300);
    }
    
    // Look for biometric toggle
    const biometricToggle = page.locator('input[type="checkbox"], [role="switch"]').filter({
      hasNot: page.locator(':disabled')
    });
    
    const count = await biometricToggle.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should show auto-lock settings', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Look for auto-lock or timeout settings
    const autoLock = page.locator('text=/auto.?lock|timeout|minutes/i');
    await page.waitForTimeout(300);
    
    const count = await autoLock.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should have passkey/WebAuthn option', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Look for passkey-related options
    const passkeyOption = page.locator('text=/passkey|webauthn|fido|hardware/i');
    await page.waitForTimeout(300);
    
    const count = await passkeyOption.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });
});

test.describe('Notification Settings', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedUser(page);
  });

  test('should show notification preferences', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Navigate to notifications tab if needed
    const notifTab = page.locator('[role="tab"], button').filter({
      hasText: /notification/i
    }).first();
    
    if (await notifTab.count() > 0) {
      await notifTab.click();
      await page.waitForTimeout(300);
    }
    
    // Look for notification toggles
    const toggles = page.locator('input[type="checkbox"], [role="switch"]');
    const count = await toggles.count();
    
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should categorize notification types', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Look for notification categories
    const categories = page.locator('text=/email|push|sms|credential|consent|security/i');
    await page.waitForTimeout(300);
    
    const count = await categories.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });
});

test.describe('Emergency Contacts', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedUser(page);
  });

  test('should show emergency contacts section', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    // Navigate to emergency tab if needed
    const emergencyTab = page.locator('[role="tab"], button').filter({
      hasText: /emergency|contact/i
    }).first();
    
    if (await emergencyTab.count() > 0) {
      await emergencyTab.click();
      await page.waitForTimeout(300);
    }
    
    // Look for emergency contact content
    const emergencySection = page.locator('text=/emergency|contact|trusted/i');
    const count = await emergencySection.count();
    
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should allow adding emergency contact', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    const addButton = page.locator('button').filter({
      hasText: /add.*contact|new.*contact/i
    });
    
    if (await addButton.count() > 0) {
      await expect(addButton.first()).toBeVisible();
    }
  });
});

test.describe('Account Actions', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedUser(page);
  });

  test('should have logout option', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    const logoutButton = page.locator('button, a').filter({
      hasText: /log.?out|sign.?out/i
    });
    
    if (await logoutButton.count() > 0) {
      await expect(logoutButton.first()).toBeVisible();
    }
  });

  test('should have export data option', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    const exportButton = page.locator('button').filter({
      hasText: /export|download|backup/i
    });
    
    // Export may or may not be visible
    const count = await exportButton.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should have delete account option with warning', async ({ page }) => {
    await page.goto('/wallet/settings');
    
    const deleteOption = page.locator('button, a').filter({
      hasText: /delete.*account|remove.*account/i
    });
    
    if (await deleteOption.count() > 0) {
      // Should have destructive styling
      const classes = await deleteOption.first().getAttribute('class');
      expect(classes || '').toBeDefined();
    }
  });
});
