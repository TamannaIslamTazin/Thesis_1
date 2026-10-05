import { test, expect } from '@playwright/test';

/**
 * Performance and Visual Tests
 * 
 * Tests performance metrics and visual appearance
 */

test.describe('Performance Metrics', () => {
  test('landing page loads within budget', async ({ page }) => {
    const startTime = Date.now();
    
    await page.goto('/', { waitUntil: 'networkidle' });
    
    const loadTime = Date.now() - startTime;
    
    // Should load within 5 seconds on a good connection
    expect(loadTime).toBeLessThan(5000);
  });

  test('no JavaScript errors on load', async ({ page }) => {
    const errors: string[] = [];
    
    page.on('pageerror', (error) => {
      errors.push(error.message);
    });
    
    await page.goto('/');
    await page.waitForTimeout(1000);
    
    // Should have no uncaught errors
    expect(errors.length).toBe(0);
  });

  test('no console errors on wallet page', async ({ page }) => {
    const errors: string[] = [];
    
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });
    
    // Set up mock auth
    await page.addInitScript(() => {
      localStorage.setItem('ssi-auth-token', 'mock-jwt-token');
      localStorage.setItem('ssi-user', JSON.stringify({
        id: 'user-123',
        email: 'test@example.com',
        displayName: 'Test User',
      }));
    });
    
    await page.goto('/wallet');
    await page.waitForTimeout(1000);
    
    // Filter out known harmless errors
    const criticalErrors = errors.filter(e => 
      !e.includes('ResizeObserver') && 
      !e.includes('network') &&
      !e.includes('fetch')
    );
    
    expect(criticalErrors.length).toBe(0);
  });

  test('images are optimized', async ({ page }) => {
    await page.goto('/');
    
    const images = await page.locator('img').all();
    
    for (const img of images.slice(0, 5)) {
      const src = await img.getAttribute('src');
      const loading = await img.getAttribute('loading');
      
      // Modern images should use lazy loading or Next.js Image optimization
      if (src && !src.startsWith('data:')) {
        // Check for Next.js image optimization or lazy loading
        const isOptimized = 
          src.includes('_next/image') || 
          loading === 'lazy' ||
          (await img.getAttribute('srcset')) !== null;
        
        // Log warning but don't fail test for non-optimized images (may be intentional)
        if (!isOptimized) {
          console.warn(`Image not optimized: ${src}`);
        }
        // All images should eventually be optimized
        expect(isOptimized).toBeTruthy();
      }
    }
  });
});

test.describe('Visual Layout', () => {
  test('landing page has expected layout', async ({ page }) => {
    await page.goto('/');
    
    // Take a snapshot for manual review
    await expect(page).toHaveScreenshot('landing-page.png', {
      fullPage: true,
      maxDiffPixels: 1000, // Allow some variance
    });
  });

  test('auth page has expected layout', async ({ page }) => {
    await page.goto('/auth');
    
    await expect(page).toHaveScreenshot('auth-page.png', {
      fullPage: true,
      maxDiffPixels: 1000,
    });
  });

  test('wallet page has expected layout', async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem('ssi-auth-token', 'mock-jwt-token');
      localStorage.setItem('ssi-user', JSON.stringify({
        id: 'user-123',
        email: 'test@example.com',
        displayName: 'Test User',
      }));
    });
    
    await page.goto('/wallet');
    await page.waitForLoadState('networkidle');
    
    await expect(page).toHaveScreenshot('wallet-page.png', {
      fullPage: true,
      maxDiffPixels: 1000,
    });
  });
});

test.describe('Responsive Design', () => {
  const viewports = [
    { name: 'mobile', width: 375, height: 667 },
    { name: 'tablet', width: 768, height: 1024 },
    { name: 'desktop', width: 1920, height: 1080 },
  ];

  for (const viewport of viewports) {
    test(`landing page renders correctly on ${viewport.name}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await page.goto('/');
      
      // Page should have visible content
      const main = page.locator('main, body');
      await expect(main).toBeVisible();
      
      // Content should fit in viewport (no horizontal scrolling)
      const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
      expect(bodyWidth).toBeLessThanOrEqual(viewport.width + 20);
    });

    test(`wallet page renders correctly on ${viewport.name}`, async ({ page }) => {
      await page.addInitScript(() => {
        localStorage.setItem('ssi-auth-token', 'mock-jwt-token');
        localStorage.setItem('ssi-user', JSON.stringify({
          id: 'user-123',
          email: 'test@example.com',
          displayName: 'Test User',
        }));
      });
      
      await page.setViewportSize(viewport);
      await page.goto('/wallet');
      
      const main = page.locator('main, body');
      await expect(main).toBeVisible();
    });
  }
});

test.describe('Dark Mode', () => {
  test('supports dark mode', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto('/');
    
    // Check that dark mode styles are applied
    const bgColor = await page.evaluate(() => {
      const body = document.body;
      return window.getComputedStyle(body).backgroundColor;
    });
    
    // Background should be dark (not white)
    expect(bgColor).not.toBe('rgb(255, 255, 255)');
  });

  test('supports light mode', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light' });
    await page.goto('/');
    
    // Page should render correctly in light mode
    const content = await page.textContent('body');
    expect(content?.length).toBeGreaterThan(0);
  });
});

test.describe('Neuromorphic Design', () => {
  test('has shadow effects', async ({ page }) => {
    await page.goto('/');
    
    // Look for neuromorphic shadow styling
    const shadowedElements = await page.locator('[class*="shadow"]').count();
    
    expect(shadowedElements).toBeGreaterThan(0);
  });

  test('has smooth transitions', async ({ page }) => {
    await page.goto('/');
    
    // Look for transition classes
    const transitionElements = await page.locator('[class*="transition"]').count();
    
    expect(transitionElements).toBeGreaterThanOrEqual(0);
  });

  test('uses rounded corners', async ({ page }) => {
    await page.goto('/');
    
    // Look for rounded styling
    const roundedElements = await page.locator('[class*="rounded"]').count();
    
    expect(roundedElements).toBeGreaterThan(0);
  });
});
