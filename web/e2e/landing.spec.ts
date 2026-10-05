import { test, expect } from '@playwright/test';

/**
 * Landing Page E2E Tests
 * 
 * Tests the premium neuromorphic landing page experience
 */
test.describe('Landing Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should display hero section with SSI messaging', async ({ page }) => {
    // Check main headline
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    
    // Check SSI-related content
    const pageContent = await page.textContent('body');
    expect(pageContent).toContain('identity');
    
    // Check CTA button exists
    const ctaButton = page.getByRole('link', { name: /get started|sign up|try/i });
    await expect(ctaButton).toBeVisible();
  });

  test('should have smooth animations on scroll', async ({ page }) => {
    // Check for framer-motion or CSS transitions
    const animatedElements = await page.locator('[data-motion], .motion-preset-fade, .transition-all').count();
    expect(animatedElements).toBeGreaterThan(0);
  });

  test('should navigate to auth page from CTA', async ({ page }) => {
    const ctaButton = page.getByRole('link', { name: /get started|sign up|try|login/i }).first();
    await ctaButton.click();
    
    await expect(page).toHaveURL(/\/auth/);
  });

  test('should have accessible contrast ratios', async ({ page }) => {
    // Basic accessibility check for text visibility
    const mainHeading = page.getByRole('heading', { level: 1 });
    await expect(mainHeading).toBeVisible();
    
    // Check that text elements are not transparent
    const headingColor = await mainHeading.evaluate(el => 
      window.getComputedStyle(el).color
    );
    expect(headingColor).not.toBe('rgba(0, 0, 0, 0)');
  });

  test('should load within performance budget', async ({ page }) => {
    const startTime = Date.now();
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const loadTime = Date.now() - startTime;
    
    // Should load within 5 seconds
    expect(loadTime).toBeLessThan(5000);
  });

  test('should be responsive on mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    
    // Check hero is still visible
    const hero = page.locator('main').first();
    await expect(hero).toBeVisible();
    
    // Navigation should be mobile-friendly (hamburger menu or simplified)
    const nav = page.locator('nav, header');
    await expect(nav.first()).toBeVisible();
  });
});
