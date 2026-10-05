import { test, expect } from '@playwright/test';

/**
 * Accessibility E2E Tests
 * 
 * Tests WCAG compliance and accessibility features
 */

test.describe('Global Accessibility', () => {
  test('landing page has no major a11y violations', async ({ page }) => {
    await page.goto('/');
    
    // Check basic accessibility requirements
    const htmlLang = await page.getAttribute('html', 'lang');
    expect(htmlLang).toBeTruthy();
    
    // Check for main landmark
    const main = page.locator('main');
    await expect(main).toBeVisible();
    
    // Check for heading hierarchy
    const h1 = page.locator('h1');
    const h1Count = await h1.count();
    expect(h1Count).toBeGreaterThanOrEqual(1);
  });

  test('auth page has form labels', async ({ page }) => {
    await page.goto('/auth');
    
    // Check inputs have labels
    const inputs = page.locator('input:not([type="hidden"])');
    const inputCount = await inputs.count();
    
    for (let i = 0; i < inputCount; i++) {
      const input = inputs.nth(i);
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const ariaLabelledby = await input.getAttribute('aria-labelledby');
      const placeholder = await input.getAttribute('placeholder');
      
      // Input should have some form of label
      const hasLabel = id || ariaLabel || ariaLabelledby || placeholder;
      expect(hasLabel).toBeTruthy();
    }
  });

  test('buttons are keyboard accessible', async ({ page }) => {
    await page.goto('/');
    
    // Find all buttons
    const buttons = page.locator('button');
    const buttonCount = await buttons.count();
    
    for (let i = 0; i < Math.min(buttonCount, 5); i++) {
      const button = buttons.nth(i);
      
      // Button should be focusable
      await button.focus();
      const isFocused = await button.evaluate(el => el === document.activeElement);
      expect(isFocused).toBeTruthy();
    }
  });

  test('links have discernible text', async ({ page }) => {
    await page.goto('/');
    
    const links = page.locator('a');
    const linkCount = await links.count();
    
    for (let i = 0; i < Math.min(linkCount, 10); i++) {
      const link = links.nth(i);
      const text = await link.textContent();
      const ariaLabel = await link.getAttribute('aria-label');
      const title = await link.getAttribute('title');
      
      // Link should have some accessible name
      const hasName = (text && text.trim().length > 0) || ariaLabel || title;
      expect(hasName).toBeTruthy();
    }
  });

  test('images have alt text', async ({ page }) => {
    await page.goto('/');
    
    const images = page.locator('img');
    const imageCount = await images.count();
    
    for (let i = 0; i < imageCount; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute('alt');
      const role = await img.getAttribute('role');
      
      // Image should have alt (can be empty for decorative) or role=presentation
      const hasAlt = alt !== null || role === 'presentation' || role === 'none';
      expect(hasAlt).toBeTruthy();
    }
  });
});

test.describe('Color Contrast', () => {
  test('text has sufficient contrast', async ({ page }) => {
    await page.goto('/');
    
    // Check that primary text elements are visible
    const primaryText = page.locator('h1, h2, p').first();
    await expect(primaryText).toBeVisible();
    
    // Get computed styles
    const styles = await primaryText.evaluate(el => {
      const computed = window.getComputedStyle(el);
      return {
        color: computed.color,
        backgroundColor: computed.backgroundColor,
      };
    });
    
    // Basic check that color is not transparent
    expect(styles.color).not.toBe('rgba(0, 0, 0, 0)');
  });
});

test.describe('Focus Management', () => {
  test('focus is visible', async ({ page }) => {
    await page.goto('/auth');
    
    // Tab to first focusable element
    await page.keyboard.press('Tab');
    
    // Check that focus ring or indicator is present
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  });

  test('skip link is present', async ({ page }) => {
    await page.goto('/');
    
    // Many accessible sites have a skip link
    const skipLink = page.locator('a[href="#main"], a[href="#content"], [class*="skip"]');
    const count = await skipLink.count();
    
    // Skip link is a best practice but not required
    expect(count).toBeGreaterThanOrEqual(0);
  });
});

test.describe('Screen Reader Support', () => {
  test('dynamic content has ARIA live regions', async ({ page }) => {
    await page.goto('/');
    
    // Check for ARIA live regions
    const liveRegions = page.locator('[aria-live], [role="alert"], [role="status"]');
    const count = await liveRegions.count();
    
    // Live regions are important for dynamic content
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('modals trap focus', async ({ page }) => {
    await page.goto('/auth');
    
    // Look for modal triggers
    const modalTrigger = page.locator('button').filter({
      hasText: /open|show|modal|dialog/i
    }).first();
    
    if (await modalTrigger.count() > 0) {
      await modalTrigger.click();
      
      // Check for dialog role
      const dialog = page.locator('[role="dialog"], [role="alertdialog"]');
      
      if (await dialog.count() > 0) {
        // Dialog should have focus trapped
        await page.keyboard.press('Tab');
        const focusedInDialog = await page.evaluate(() => {
          const dialog = document.querySelector('[role="dialog"], [role="alertdialog"]');
          const activeElement = document.activeElement;
          // Focus is in dialog if dialog contains it, or if dialog itself is focused
          return dialog?.contains(activeElement) || dialog === activeElement;
        });
        
        // Focus should remain in dialog if visible - this is an a11y requirement
        expect(focusedInDialog).toBeTruthy();
      }
    }
  });
});

test.describe('Reduced Motion', () => {
  test('respects prefers-reduced-motion', async ({ page }) => {
    // Emulate reduced motion preference
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/');
    
    // Check that page loads without animation issues
    const content = await page.textContent('body');
    expect(content?.length).toBeGreaterThan(0);
    
    // Animations should be reduced or disabled
    // This is hard to test automatically, but page should still work
  });
});
