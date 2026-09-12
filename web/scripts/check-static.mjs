#!/usr/bin/env node
/**
 * Verify a built static snapshot edition with Playwright (docs/10-static-snapshot.md section 4): loads the demo
 * routes under hash routing, opens the analyst drawer and sends a precomputed question plus an unmatched one, and
 * fails on any page error, failed request, HTTP >= 400 response, visible "Request failed" state or missing
 * "Static edition" badge.
 *
 *   node scripts/check-static.mjs http://127.0.0.1:4174/      # check an already served dist-static
 *   node scripts/check-static.mjs --dir dist-static            # serve the folder on a free port, check, exit
 *
 * Env: CHECK_ALERT, CHECK_STORYLINE, CHECK_NODE override the demo ids; CHECK_HEADLESS=0 shows the browser;
 * CHECK_SCREENSHOTS=<dir> saves a screenshot per step.
 */
import { createReadStream, existsSync, mkdirSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const here = path.dirname(fileURLToPath(import.meta.url))
const webDir = path.resolve(here, '..')
const args = process.argv.slice(2)
const dirFlag = args.indexOf('--dir')
const serveDir = dirFlag >= 0 ? path.resolve(webDir, args[dirFlag + 1] ?? 'dist-static') : null
const baseArg = args.find((a, i) => !a.startsWith('--') && (dirFlag < 0 || i !== dirFlag + 1))
const screenshotDir = process.env.CHECK_SCREENSHOTS ? path.resolve(webDir, process.env.CHECK_SCREENSHOTS) : null

const ALERT = process.env.CHECK_ALERT ?? 'alert:falcon:ldt-a009'
const STORYLINE = process.env.CHECK_STORYLINE ?? 'storyline:derived:embercast-larkspur'
const NODE = process.env.CHECK_NODE ?? 'endpoint:falcon:aid-bas01'
const UNMATCHED_QUESTION = 'What is the airspeed velocity of an unladen swallow?'

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.map': 'application/json' }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** Minimal static file server (no SPA fallback on purpose: the static edition must work from plain files). */
function serveStatic(dir) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const rel = decodeURIComponent((req.url ?? '/').split('?')[0].split('#')[0])
      let file = path.resolve(dir, `.${rel}`)
      if (!file.startsWith(dir)) file = path.join(dir, 'index.html')
      if (existsSync(file) && statSync(file).isDirectory()) file = path.join(file, 'index.html')
      if (!existsSync(file) || !statSync(file).isFile()) {
        res.statusCode = 404
        res.end('not found')
        return
      }
      res.setHeader('content-type', MIME[path.extname(file)] ?? 'application/octet-stream')
      createReadStream(file).pipe(res)
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}/` }))
  })
}

async function launchBrowser() {
  const headless = process.env.CHECK_HEADLESS !== '0'
  try {
    return await chromium.launch({ headless })
  } catch (e) {
    for (const candidate of ['/opt/pw-browsers/chromium-1194/chrome-linux/chrome', '/opt/pw-browsers/chromium/chrome-linux/chrome']) {
      if (existsSync(candidate)) return chromium.launch({ headless, executablePath: candidate })
    }
    throw e
  }
}

async function main() {
  let server = null
  let base = baseArg
  if (serveDir) {
    if (!existsSync(path.join(serveDir, 'index.html'))) throw new Error(`${serveDir}/index.html does not exist; run scripts/build_static.sh first`)
    ;({ server, url: base } = await serveStatic(serveDir))
    console.log(`serving ${path.relative(process.cwd(), serveDir)} at ${base}`)
  }
  if (!base) throw new Error('usage: node scripts/check-static.mjs <base url> | --dir <dist-static>')
  if (!base.endsWith('/')) base += '/'

  const problems = []
  const warnings = []
  const note = (ok, label, detail = '') => {
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}`)
    if (!ok) problems.push(`${label}${detail ? `: ${detail}` : ''}`)
  }

  // Pick a precomputed global question straight from the snapshot so the check works against any exporter output.
  let question = 'Which credentials used in cloud API calls today were seen being stolen on an endpoint?'
  try {
    const chat = await (await fetch(`${base}snapshot/chat.json`)).json()
    const global = (chat.answers ?? []).find((a) => (a.context_key ?? '') === '')
    if (global) question = global.question
    note(true, 'snapshot/chat.json', `${chat.answers?.length ?? 0} answers, ${Object.keys(chat.suggestions ?? {}).length} suggestion contexts`)
  } catch (e) {
    note(false, 'snapshot/chat.json', e.message)
  }
  try {
    const manifest = await (await fetch(`${base}snapshot/manifest.json`)).json()
    note(manifest.version === 1, 'snapshot/manifest.json', `version ${manifest.version}, ${manifest.node_count} nodes, ${manifest.edge_count} edges, ${manifest.alert_count} alerts`)
  } catch (e) {
    note(false, 'snapshot/manifest.json', e.message)
  }
  // The lowest-ranked alert almost never has a precomputed context, so it exercises the adapter's lite context path.
  let liteAlert = null
  try {
    const alerts = await (await fetch(`${base}snapshot/alerts.json`)).json()
    liteAlert = alerts.items?.at(-1)?.id ?? null
    note(!!liteAlert, 'snapshot/alerts.json', `${alerts.items?.length ?? 0} alerts, lite-context probe ${liteAlert ?? 'n/a'}`)
  } catch (e) {
    note(false, 'snapshot/alerts.json', e.message)
  }
  try {
    const html = await (await fetch(base)).text()
    note(/(src|href)="\.\/assets\//.test(html), 'index.html uses relative asset URLs (./assets/...)')
    note(!/(src|href)="\/(assets|favicon)/.test(html), 'index.html has no root-absolute asset URLs')
  } catch (e) {
    note(false, 'index.html', e.message)
  }

  const browser = await launchBrowser()
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: 'dark' })
  const pageErrors = []
  const failedRequests = []
  const badResponses = []
  page.on('pageerror', (err) => pageErrors.push(err.message))
  page.on('console', (msg) => {
    if (msg.type() === 'error') warnings.push(`console.error: ${msg.text().slice(0, 200)}`)
  })
  page.on('requestfailed', (req) => {
    const reason = req.failure()?.errorText ?? 'failed'
    if (reason.includes('ERR_ABORTED')) warnings.push(`aborted: ${req.url()}`)
    else failedRequests.push(`${req.url()} (${reason})`)
  })
  page.on('response', (res) => {
    if (res.status() >= 400) badResponses.push(`${res.status()} ${res.url()}`)
  })
  if (screenshotDir) mkdirSync(screenshotDir, { recursive: true })
  let shot = 0
  const snap = async (name) => {
    if (screenshotDir) await page.screenshot({ path: path.join(screenshotDir, `${String(++shot).padStart(2, '0')}-${name}.png`) })
  }

  const routes = [
    ['dashboard', '#/', 'text=Contextual priority'],
    ['alerts', '#/alerts', 'table tbody tr'],
    ['alert-detail-graph', `#/alerts/${encodeURIComponent(ALERT)}?tab=graph`, 'text=Contextual score breakdown'],
    ...(liteAlert && liteAlert !== ALERT ? [['alert-detail-lite', `#/alerts/${encodeURIComponent(liteAlert)}?tab=graph`, 'text=Contextual score breakdown']] : []),
    ['storyline', `#/storylines/${encodeURIComponent(STORYLINE)}`, 'text=Kill chain'],
    ['explorer', `#/explorer?id=${encodeURIComponent(NODE)}`, 'text=On canvas'],
    ['threat-intel-exposure', '#/threat-intel?tab=exposure', 'table tbody tr'],
  ]
  try {
    for (const [name, route, selector] of routes) {
      await page.goto(base + route, { waitUntil: 'networkidle' })
      const found = await page.waitForSelector(selector, { timeout: 30_000 }).then(() => true).catch(() => false)
      await page.waitForLoadState('networkidle').catch(() => undefined)
      await sleep(600)
      const requestFailed = await page.locator('text=Request failed').count()
      note(found && requestFailed === 0, `route ${route}`, found ? (requestFailed ? `${requestFailed} "Request failed" state(s) visible` : selector) : `timed out waiting for ${selector}`)
      await snap(name)
    }
    const badge = await page.locator('text=Static edition').first().isVisible().catch(() => false)
    note(badge, 'header badge "Static edition" visible')
    const mockBadge = await page.locator('text=Mock data').count()
    note(mockBadge === 0, 'no "Mock data" badge')

    // Analyst drawer: a precomputed question replays its answer; an unmatched one gets the static-edition help answer.
    await page.goto(base + `#/alerts/${encodeURIComponent(ALERT)}?tab=graph`, { waitUntil: 'networkidle' })
    await page.waitForSelector('text=Contextual score breakdown', { timeout: 30_000 }).catch(() => undefined)
    await page.locator("[data-testid='analyst-toggle']").first().click()
    const input = page.locator("[data-testid='analyst-input']")
    await input.waitFor({ timeout: 10_000 })
    // chat.json is the largest snapshot file; give the suggestions query time to fetch it.
    const suggestionsShown = await page.waitForSelector('text=Suggested questions', { timeout: 30_000 }).then(() => true).catch(() => false)
    note(suggestionsShown, 'analyst suggestions rendered')
    await input.fill(question)
    await input.press('Enter')
    const answered = await page.waitForSelector('text=confidence', { timeout: 60_000 }).then(() => true).catch(() => false)
    await sleep(500)
    const drawer = page.locator('aside[aria-label="Analyst"]')
    const chatError = await drawer.locator('div[class*="border-sev-critical"]').count()
    const footer = answered ? await drawer.getByText(/\d+ tool calls?/).last().textContent().catch(() => '') : ''
    note(answered && chatError === 0, `analyst answered "${question.slice(0, 60)}${question.length > 60 ? '…' : ''}"`, answered ? (chatError ? `${chatError} error box(es)` : (footer ?? '').trim()) : 'no answer within 60 s')
    await snap('analyst-answer')
    await input.fill(UNMATCHED_QUESTION)
    await input.press('Enter')
    const fallback = await page.waitForSelector('text=Prepared questions', { timeout: 30_000 }).then(() => true).catch(() => false)
    note(fallback, 'unmatched question gets the static-edition help answer')
    await snap('analyst-fallback')
  } finally {
    await browser.close().catch(() => undefined)
    server?.close()
  }

  note(pageErrors.length === 0, 'zero page errors', pageErrors.join(' | ').slice(0, 400))
  note(failedRequests.length === 0, 'zero failed requests', failedRequests.join(' | ').slice(0, 400))
  note(badResponses.length === 0, 'zero HTTP >= 400 responses', badResponses.join(' | ').slice(0, 400))
  for (const w of [...new Set(warnings)].slice(0, 10)) console.log(`warn ${w}`)
  if (problems.length) {
    console.log(`\n${problems.length} problem(s)`)
    process.exit(1)
  }
  console.log('\nstatic edition check passed')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
