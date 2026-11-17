import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import {
  attachAuth,
  loginAccount,
  logoutAccount,
  registerAccount,
  type AuthenticatedRequest,
} from './server/auth/auth.ts';
import {
  deleteScanById,
  getScanReportById,
  getSettingsForOwner,
  listScansForOwner,
  saveScanReport,
  updateScanAIAnalysis,
  upsertSettingsForOwner,
} from './server/db/database.ts';
import { checkScanRateLimit, normalizeInputUrl } from './server/security/ssrf.ts';
import {
  calculateReadinessScore,
  parseHtmlDocument,
  runAvailabilityCheck,
  runBrokenLinkCheck,
  runPerformanceAnalysis,
  runSecurityAnalysis,
  runSeoAnalysis,
} from './server/scanner/analyzer.ts';
import { generateAIWebsiteAnalysis } from './server/ai/analyst.ts';
import type { ScanReport, ScanStageId, ScanStageStatus } from './src/types/scan.ts';

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.disable('x-powered-by');
  app.use(express.json({ limit: '512kb' }));
  app.use(cookieParser());

  // Basic security headers for LaunchGuard AI itself
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  app.use('/api', attachAuth);

  // --- Authentication Routes ---
  app.get('/api/auth/me', (req, res) => {
    const authReq = req as AuthenticatedRequest;
    res.json({
      user: authReq.authUser ?? null,
      workspaceMode: authReq.authUser ? 'account' : 'session',
    });
  });

  app.post('/api/auth/register', (req, res) => {
    registerAccount(req as AuthenticatedRequest, res);
  });

  app.post('/api/auth/login', (req, res) => {
    loginAccount(req as AuthenticatedRequest, res);
  });

  app.post('/api/auth/logout', (req, res) => {
    logoutAccount(req as AuthenticatedRequest, res);
  });

  // --- Settings Routes ---
  app.get('/api/settings', (req, res) => {
    const authReq = req as AuthenticatedRequest;
    const settings = getSettingsForOwner(authReq.ownerKey);
    res.json({ settings });
  });

  app.put('/api/settings', (req, res) => {
    const authReq = req as AuthenticatedRequest;
    const updated = upsertSettingsForOwner(authReq.ownerKey, req.body ?? {});
    res.json({ settings: updated });
  });

  // --- Scan History Routes ---
  app.get('/api/scans', (req, res) => {
    const authReq = req as AuthenticatedRequest;
    const scans = listScansForOwner(authReq.ownerKey, 50);
    res.json({ scans });
  });

  app.get('/api/scans/:id', (req, res) => {
    const report = getScanReportById(req.params.id, req.ownerKey);
    if (!report) {
      res.status(404).json({ error: 'Scan report not found.' });
      return;
    }
    res.json({ report });
  });

  app.delete('/api/scans/:id', (req, res) => {
    const deleted = deleteScanById(req.params.id, req.ownerKey);
    if (!deleted) {
      res.status(404).json({ error: 'Scan report not found.' });
      return;
    }
    res.json({ ok: true });
  });

  app.post('/api/scans/:id/reanalyze-ai', async (req, res) => {
    const existing = getScanReportById(req.params.id, req.ownerKey);
    if (!existing) {
      res.status(404).json({ error: 'Scan report not found.' });
      return;
    }

    const aiResult = await generateAIWebsiteAnalysis(existing);
    const updated = updateScanAIAnalysis(req.params.id, req.ownerKey, aiResult);
    res.json({ report: updated });
  });

  // --- Real-time Streaming Website Scanner ---
  app.post('/api/scans/stream', async (req, res) => {
    const authReq = req as AuthenticatedRequest;
    const { url: rawUrl, authorized } = (req.body ?? {}) as {
      url?: string;
      authorized?: boolean;
    };

    const settings = getSettingsForOwner(authReq.ownerKey);

    if (settings.requireAuthConfirmation && !authorized) {
      res.status(400).json({
        error:
          'Confirm that you own or have permission to test this website before scanning.',
      });
      return;
    }

    let normalizedUrl: string;
    try {
      normalizedUrl = normalizeInputUrl(rawUrl ?? '').toString();
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'Invalid URL provided.',
      });
      return;
    }

    const rateKey = `${authReq.ownerKey}:${req.ip ?? 'local'}`;
    const rate = checkScanRateLimit(rateKey, 10, 60_000);
    if (!rate.allowed) {
      res.status(429).json({
        error: `Rate limit reached. Please wait ${rate.retryAfterSec ?? 30} seconds before starting another scan.`,
      });
      return;
    }

    // Stream NDJSON events as each real stage executes
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const emit = (payload: Record<string, unknown>) => {
      if (!res.writableEnded) {
        res.write(`${JSON.stringify(payload)}\n`);
      }
    };

    const emitStage = (
      id: ScanStageId,
      status: ScanStageStatus,
      detail?: string,
      durationMs?: number
    ) => {
      emit({ type: 'stage', id, status, detail, durationMs });
    };

    const scanStartedAt = Date.now();

    try {
      // Stage 1: Availability & Redirects
      emitStage('availability', 'running', `Connecting to ${normalizedUrl}`);
      const s1Start = Date.now();
      const { availability, fetchResult } = await runAvailabilityCheck(
        normalizedUrl,
        settings.requestTimeoutMs
      );
      emitStage(
        'availability',
        availability.reachable ? 'completed' : 'warning',
        `HTTP ${availability.statusCode} · ${availability.responseTimeMs}ms${
          availability.redirectChain.length > 0
            ? ` · ${availability.redirectChain.length} redirect(s)`
            : ''
        }`,
        Date.now() - s1Start
      );

      // Stage 2: Security Configuration & TLS
      emitStage('security', 'running', 'Inspecting TLS certificate & HTTP security headers');
      const s2Start = Date.now();
      const security = await runSecurityAnalysis(
        availability,
        fetchResult.headers,
        settings.requestTimeoutMs
      );
      const secFails = security.findings.filter((f) => f.status === 'fail').length;
      emitStage(
        'security',
        secFails > 0 ? 'warning' : 'completed',
        `${security.httpsEnabled ? 'HTTPS active' : 'No HTTPS'} · ${
          security.findings.filter((f) => f.status === 'pass').length
        }/${security.findings.length} checks passed`,
        Date.now() - s2Start
      );

      // Parse HTML safely (never executes scripts)
      const $ = parseHtmlDocument(fetchResult.body);

      // Stage 3: Performance Analysis
      emitStage('performance', 'running', 'Measuring payload size, images & external resources');
      const s3Start = Date.now();
      const performance = runPerformanceAnalysis(fetchResult, $);
      emitStage(
        'performance',
        'completed',
        `${performance.htmlSizeKb} KB HTML · ${performance.imageCount} images · ${performance.totalExternalResources} external assets`,
        Date.now() - s3Start
      );

      // Stage 4: SEO Inspection
      emitStage('seo', 'running', 'Checking title, meta tags, headings & OpenGraph');
      const s4Start = Date.now();
      const seo = runSeoAnalysis($);
      emitStage(
        'seo',
        'completed',
        `${seo.title ? 'Title found' : 'Missing title'} · ${
          seo.metaDescription ? 'Description set' : 'No description'
        }`,
        Date.now() - s4Start
      );

      // Stage 5: Broken Link Verification
      emitStage(
        'links',
        'running',
        `Sampling up to ${settings.maxLinksToCheck} internal links safely`
      );
      const s5Start = Date.now();
      const links = await runBrokenLinkCheck(
        availability.finalUrl,
        $,
        settings.maxLinksToCheck,
        settings.requestTimeoutMs
      );
      emitStage(
        'links',
        links.brokenCount > 0 ? 'warning' : 'completed',
        links.checkedCount > 0
          ? `${links.healthyCount}/${links.checkedCount} healthy (${links.brokenCount} broken)`
          : 'No internal sub-page links found on document',
        Date.now() - s5Start
      );

      // Transparent deterministic Launch Readiness Scoring
      const { score, allFindings } = calculateReadinessScore(
        availability,
        security,
        performance,
        seo,
        links
      );

      const baseReport: Omit<ScanReport, 'ai'> = {
        id: crypto.randomUUID(),
        url: normalizedUrl,
        finalUrl: availability.finalUrl,
        scannedAt: new Date().toISOString(),
        totalDurationMs: Date.now() - scanStartedAt,
        availability,
        security,
        performance,
        seo,
        links,
        score,
        allFindings,
      };

      // Stage 6: AI Website Analyst
      emitStage('ai', 'running', 'Sending verified scan results to AI Website Analyst');
      const s6Start = Date.now();
      const aiResult = await generateAIWebsiteAnalysis(baseReport);
      emitStage(
        'ai',
        aiResult.status === 'completed' ? 'completed' : 'warning',
        aiResult.status === 'completed'
          ? 'Plain-language audit summary and fix steps ready'
          : aiResult.errorMessage || 'AI analyst unavailable',
        Date.now() - s6Start
      );

      const finalReport: ScanReport = {
        ...baseReport,
        totalDurationMs: Date.now() - scanStartedAt,
        ai: aiResult,
      };

      saveScanReport(authReq.ownerKey, authReq.authUser?.id ?? null, finalReport);

      emit({ type: 'complete', report: finalReport });
      res.end();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Website scan failed.';
      emit({ type: 'error', error: message });
      res.end();
    }
  });

  // Vite dev middleware or production static assets
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`LaunchGuard AI server listening on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start LaunchGuard AI server:', err);
  process.exit(1);
});
