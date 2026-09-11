#!/usr/bin/env node
/**
 * Capture the demo screens from the mock-backed UI (VITE_MOCK=1) into docs/screenshots/mock-*.png at 1440x900.
 *
 *   node scripts/screenshot.mjs              # starts a Vite dev server on :5199 with VITE_MOCK=1, captures, exits
 *   SCREENSHOT_BASE=http://127.0.0.1:8000 node scripts/screenshot.mjs   # capture an already running server instead
 *
 * Env: SCREENSHOT_OUT (default ../docs/screenshots), SCREENSHOT_PORT (default 5199), SCREENSHOT_PREFIX (default "mock-").
 * Uses the preinstalled Playwright Chromium; falls back to /opt/pw-browsers/chromium when the default lookup fails.
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const here = path.dirname(fileURLToPath(import.meta.url))
const webDir = path.resolve(here, '..')
const outDir = path.resolve(webDir, process.env.SCREENSHOT_OUT ?? '../docs/screenshots')
const port = Number(process.env.SCREENSHOT_PORT ?? 5199)
const prefix = process.env.SCREENSHOT_PREFIX ?? 'mock-'
const externalBase = process.env.SCREENSHOT_BASE
const base = externalBase ?? `http://127.0.0.1:${port}`

const ALERT = 'alert:falcon:ldt-a009'
const STORYLINE = 'storyline:derived:embercast-larkspur'
const SEED = 'endpoint:falcon:aid-bas01'
const CHAT = 'Which credentials used in cloud API calls today were seen being stolen on an endpoint?'

const PAGES = [
  ['dashboard', '/', 'text=Contextual priority'],
  ['alerts', '/alerts', 'table tbody tr'],
  ['alert-detail-graph-context', `/alerts/${ALERT}?tab=graph`, 'text=Contextual score breakdown'],
  ['alert-detail-flat-view', `/alerts/${ALERT}?tab=flat`, 'text=console shows'],
  ['storyline-embercast', `/storylines/${STORYLINE}`, 'text=Kill chain'],
  ['explorer', `/explorer?id=${SEED}`, 'text=On canvas'],
  ['threat-intel-exposure', '/threat-intel?tab=exposure', 'table tbody tr'],
]

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function waitForServer(url, ms = 90_000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (res.ok) return
    } catch {
      /* not up yet */
    }
    await sleep(500)
  }
  throw new Error(`server at ${url} did not come up within ${ms} ms`)
}

function startVite() {
  const bin = path.join(webDir, 'node_modules', 'vite', 'bin', 'vite.js')
  const child = spawn(process.execPath, [bin, '--port', String(port), '--strictPort', '--host', '127.0.0.1'], {
    cwd: webDir,
    env: { ...process.env, VITE_MOCK: '1', BROWSER: 'none', NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  child.stdout.on('data', (d) => process.env.SCREENSHOT_VERBOSE && process.stdout.write(`[vite] ${d}`))
  child.stderr.on('data', (d) => process.stderr.write(`[vite] ${d}`))
  return child
}

async function launchBrowser() {
  try {
    return await chromium.launch()
  } catch (e) {
    for (const candidate of ['/opt/pw-browsers/chromium', '/opt/pw-browsers/chromium-1194/chrome-linux/chrome']) {
      if (existsSync(candidate)) return chromium.launch({ executablePath: candidate })
    }
    throw e
  }
}

async function settle(page, selector) {
  await page.waitForLoadState('networkidle').catch(() => undefined)
  if (selector) await page.waitForSelector(selector, { timeout: 20_000 }).catch(() => undefined)
  await sleep(1800) // let cytoscape finish its layout animation
}

async function main() {
  mkdirSync(outDir, { recursive: true })
  const vite = externalBase ? null : startVite()
  const captured = []
  let browser
  try {
    await waitForServer(base + '/')
    browser = await launchBrowser()
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: 'dark' })
    page.on('pageerror', (err) => console.error('[page error]', err.message))
    // Warm up: the dev server compiles on first request; the mock dataset builds lazily.
    await page.goto(base + '/', { waitUntil: 'networkidle' })
    await sleep(1500)
    for (const [name, route, selector] of PAGES) {
      await page.goto(base + route, { waitUntil: 'networkidle' })
      await settle(page, selector)
      const file = path.join(outDir, `${prefix}${name}.png`)
      await page.screenshot({ path: file })
      captured.push(file)
      console.log('captured', path.relative(process.cwd(), file))
    }
    // Analyst drawer mid-answer: tool-call chips and the streaming narrative over the alert's evidence canvas.
    await page.goto(base + `/alerts/${ALERT}?tab=graph`, { waitUntil: 'networkidle' })
    await settle(page, 'text=Contextual score breakdown')
    await page.locator("[data-testid='analyst-toggle']").first().click()
    const input = page.locator("[data-testid='analyst-input']")
    await input.waitFor({ timeout: 10_000 })
    await input.fill(CHAT)
    await input.press('Enter')
    await page.waitForSelector('.caret, .animate-spin', { timeout: 15_000 }).catch(() => undefined)
    await sleep(900)
    const mid = path.join(outDir, `${prefix}analyst-drawer.png`)
    await page.screenshot({ path: mid })
    captured.push(mid)
    console.log('captured', path.relative(process.cwd(), mid))
    await page.waitForSelector('text=confidence', { timeout: 60_000 }).catch(() => undefined)
    await sleep(1200)
    const done = path.join(outDir, `${prefix}analyst-drawer-answer.png`)
    await page.screenshot({ path: done })
    captured.push(done)
    console.log('captured', path.relative(process.cwd(), done))
  } finally {
    await browser?.close().catch(() => undefined)
    if (vite) {
      vite.kill('SIGTERM')
      await sleep(300)
      if (!vite.killed) vite.kill('SIGKILL')
    }
  }
  console.log(`\n${captured.length} screenshots in ${outDir}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
