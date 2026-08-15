# WebMCP Attack Surface Scanner

A Chrome extension that discovers [WebMCP](https://github.com/webmachinelearning/webmcp) tools (`document.modelContext`) exposed by the current page and flags common security issues:

- **Confirmed IDOR** — active probing: calls tools with varied ID-shaped parameters and diffs the identity fields in the responses, not just name-based guessing
- **Prompt injection in tool metadata** — hidden instructions aimed at an AI agent, embedded in a tool's `description` field rather than its actual behavior
- **Destructive actions without a consent gate** — tools that mutate state (delete/cancel/transfer/etc.) with no confirmation parameter or step
- **Unconstrained input schemas** — free-form string parameters that read like a passthrough to a backend command/query

## Install

No Chrome Web Store listing yet — load it unpacked:

1. **Code → Download ZIP** (top of this page), or `git clone` this repo
2. Unzip it
3. Open `chrome://extensions` in Chrome
4. Enable **Developer mode** (top right toggle)
5. Click **Load unpacked** → select the unzipped folder
6. Open any page that registers WebMCP tools, click the extension icon, click **Scan this page**

## Free vs Pro

**Free** — regex-based heuristics + active IDOR probing (real tool calls with varied IDs, not just pattern matching on names).

**Pro ($5, [get a key](https://nowpayments.io/payment/?iid=5936649146))** — adds an AI triage pass using Claude, which catches semantically-obvious issues that regex misses (novel phrasing, no keyword match). Pro is BYOK: you paste your own Anthropic API key into the popup. It's stored only in `chrome.storage.local` on your machine and is only ever sent to `api.anthropic.com` — never to us. You pay Anthropic directly for the tokens the triage pass uses; we don't see or markup that cost.

After paying, email the address on the payment page for your license key, then paste it into the popup's license field.

## How it works

- `inject.js` runs in the page's **MAIN world** (via `chrome.scripting.executeScript({world: "MAIN"})`) so it can see `document.modelContext` exactly as the page's own JS would. It discovers tools via `getTools()`, runs the heuristic checks, and for read-style tools with an ID-shaped parameter, actively calls the tool with several different IDs and checks whether the returned identity fields (name/email/etc.) change — a real, confirmed IDOR rather than a guess.
- `content.js` runs in the extension's isolated world and relays results from the page to the popup via `chrome.runtime.sendMessage` (the MAIN world has no `chrome.*` access).
- `popup.js` renders findings, and — for Pro users with an API key set — sends only the tools *not* already flagged by heuristics to Claude for a semantic second pass, to keep token usage down.

## Scope

Only scan sites you own or are explicitly authorized to test. This tool makes real tool calls (including the active IDOR probe) — treat it like any other active security testing tool.
