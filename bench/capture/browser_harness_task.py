"""Deterministic Browser Harness choreography for the external-CDP cohort.

This file is executed by ``browser-harness`` with its helper functions already
present in the global namespace. It is not a standalone Python program.
"""

import json
import os


capture_url = os.environ["FCAPTCHA_CAPTURE_URL"]
capture_mode = os.environ["FCAPTCHA_CAPTURE_MODE"]
if capture_mode not in {"form", "invisible", "widget"}:
    raise RuntimeError(f"unsupported capture mode: {capture_mode}")


def click_selector(selector):
    box = js(
        "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
        "if(!e)return null;const r=e.getBoundingClientRect();"
        "return {x:r.left+r.width/2,y:r.top+r.height/2};})()"
    )
    if not box:
        raise RuntimeError(f"element not found: {selector}")
    click_at_xy(box["x"], box["y"])


goto_url(capture_url)
if not wait_for_element("body[data-ready=true]", timeout=20, visible=True):
    raise RuntimeError("capture page did not become ready")

fill_input("#name", "Browser test", timeout=10)
click_selector('a[href="#footer"]')
wait(0.5)
scroll(640, 700, dy=-1200)
wait(0.5)

if capture_mode == "form":
    # The shipped automatic form integration intercepts the first submit,
    # scores it, adds the token, and then requestSubmit()s the approved form.
    click_selector("#submit")
elif capture_mode == "invisible":
    click_selector("#submit")
else:
    click_selector(".fcaptcha-checkbox")

# Blocked form and widget submissions intentionally do not receive a token or
# render a success callback. The recorder, not page text, is the completion
# authority. Keep the browser alive long enough for scoring and the separate
# post-score research observation to finish.
wait(10)
result = js("document.querySelector('#result')?.textContent || ''")

print({
    "page": page_info(),
    "name": js("document.querySelector('#name')?.value || ''"),
    "result": result,
})
