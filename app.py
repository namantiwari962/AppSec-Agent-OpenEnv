import gradio as gr
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from server.environment import AppSecEnvironment
from server.models import AppSecAction

# ──────────────────────────────────────────────────────────────────────────────
# Environment (shared, reset per evaluation)
# ──────────────────────────────────────────────────────────────────────────────
env = AppSecEnvironment(target_dir="target_app", server_dir="server")

REFERENCE_PATCH = '''\
import sqlite3
import html

def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'secretpass'))
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('user', 'userpass'))
    conn.commit()
    return conn

def login(conn, username, password):
    cursor = conn.cursor()
    # FIXED: Parameterized query prevents SQL Injection
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    try:
        cursor.execute(query, (username, password))
        user = cursor.fetchone()
        if user:
            return True
        return False
    except sqlite3.Error:
        return False

def render_profile(username):
    # FIXED: HTML entity escaping prevents XSS
    safe_username = html.escape(username)
    return f"<h1>Welcome to your profile, {safe_username}!</h1>"

def read_file(filename):
    # FIXED: Path canonicalization prevents Path Traversal / LFI
    base_dir = os.path.realpath("public")
    requested_path = os.path.realpath(os.path.join(base_dir, filename))
    if not requested_path.startswith(base_dir + os.sep) and requested_path != base_dir:
        return "Access denied."
    try:
        with open(requested_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found."
'''


# ──────────────────────────────────────────────────────────────────────────────
# Core Evaluation Logic
# ──────────────────────────────────────────────────────────────────────────────
def evaluate_patch(patch_code: str):
    """
    Run the agent's patch through the AppSecEnvironment and return
    formatted results for Gradio display.
    """
    if not patch_code.strip():
        return (
            "⚠️ Please enter a Python patch to evaluate.",
            "—",
            "—",
            "—",
            "—",
            "—",
        )

    env.reset()
    action = AppSecAction(patch_code=patch_code)
    obs, reward, done, info = env.step(action)

    # ── Reward Badge ──────────────────────────────────────────────
    if reward == 50.0:
        reward_badge = "🟢 +50 — OPTIMAL DEFENSE! All vulnerabilities patched."
    elif reward == -10.0:
        reward_badge = "🟡 -10 — Partial / failed attempt."
    else:
        reward_badge = "🔴 -100 — Episode failed. Server compromised or anti-cheat violation."

    # ── Vulnerability Status ──────────────────────────────────────
    vulns = info.get("vulnerabilities", {})
    sqli = "✅ Fixed" if vulns.get("sqli_fixed") else "❌ Vulnerable"
    xss  = "✅ Fixed" if vulns.get("xss_fixed")  else "❌ Vulnerable"
    lfi  = "✅ Fixed" if vulns.get("lfi_fixed")   else "❌ Vulnerable"

    # ── Test Output ───────────────────────────────────────────────
    test_output = obs.stdout or "(no pytest output)"
    if obs.stderr:
        test_output += f"\n\nSTDERR:\n{obs.stderr}"

    return reward_badge, sqli, xss, lfi, test_output, obs.file_content


def load_vulnerable_code():
    """Load the original vulnerable code for the editor."""
    env.reset()
    return env.original_content


def load_reference_patch():
    """Load the reference secure patch."""
    return REFERENCE_PATCH


# ──────────────────────────────────────────────────────────────────────────────
# Gradio UI
# ──────────────────────────────────────────────────────────────────────────────
CSS = """
#title { text-align: center; }
#subtitle { text-align: center; color: #666; }
.vuln-box { border-radius: 8px; padding: 8px; }
.reward-box { font-size: 1.1em; font-weight: bold; }
"""

with gr.Blocks(
    title="🔐 AppSec RL Agent — OpenEnv Hackathon Demo",
    theme=gr.themes.Soft(primary_hue="indigo", neutral_hue="slate"),
    css=CSS,
) as demo:

    # ── Header ─────────────────────────────────────────────────────
    gr.Markdown(
        """
        # 🔐 AppSec RL Agent — OpenEnv Hackathon
        **Red Team vs. Blue Team** · Powered by GRPO + Unsloth + LLaMA-3-8B
        """,
        elem_id="title",
    )
    gr.Markdown(
        "An RL-trained Blue Team agent patches a vulnerable Python app to stop Red Team exploits.",
        elem_id="subtitle",
    )

    # ── Main Tabs ──────────────────────────────────────────────────
    with gr.Tabs():

        # ─── Tab 1: Interactive Patch Evaluator ───────────────────
        with gr.TabItem("🛡️ Patch Evaluator"):
            gr.Markdown(
                "### How it works\n"
                "Write or paste a patched version of the vulnerable app below and click **Evaluate**. "
                "The environment will run pytest security tests and functional tests, then return a reward."
            )

            with gr.Row():
                with gr.Column(scale=1):
                    patch_input = gr.Code(
                        label="📝 Your Patched Code",
                        language="python",
                        value=env.original_content,
                        lines=28,
                        elem_id="patch_input",
                    )
                    with gr.Row():
                        eval_btn     = gr.Button("🚀 Evaluate Patch", variant="primary")
                        load_vuln    = gr.Button("↩️ Load Vulnerable", variant="secondary")
                        load_ref     = gr.Button("✅ Load Reference Fix", variant="secondary")

                with gr.Column(scale=1):
                    reward_out = gr.Textbox(
                        label="🏆 Reward Signal",
                        interactive=False,
                        elem_classes=["reward-box"],
                    )
                    with gr.Row():
                        sqli_out = gr.Textbox(label="💉 SQLi", interactive=False, scale=1)
                        xss_out  = gr.Textbox(label="📜 XSS",  interactive=False, scale=1)
                        lfi_out  = gr.Textbox(label="📂 LFI",  interactive=False, scale=1)

                    test_output = gr.Textbox(
                        label="🧪 Pytest Output",
                        interactive=False,
                        lines=12,
                    )
                    applied_code = gr.Code(
                        label="📄 Applied File (what the env saw)",
                        language="python",
                        interactive=False,
                        lines=10,
                    )

            eval_btn.click(
                fn=evaluate_patch,
                inputs=[patch_input],
                outputs=[reward_out, sqli_out, xss_out, lfi_out, test_output, applied_code],
            )
            load_vuln.click(fn=load_vulnerable_code, outputs=[patch_input])
            load_ref.click(fn=load_reference_patch,  outputs=[patch_input])

        # ─── Tab 2: Vulnerability Explorer ───────────────────────
        with gr.TabItem("🔍 Vulnerability Explorer"):
            gr.Markdown("### 🎯 The Three Vulnerabilities")

            with gr.Row():
                with gr.Column():
                    gr.Markdown("#### 💉 1. SQL Injection (SQLi)")
                    gr.Code(
                        value=(
                            '# ❌ VULNERABLE\n'
                            'query = f"SELECT * FROM users WHERE username = \'{username}\' '
                            'AND password = \'{password}\'"\n'
                            'cursor.execute(query)\n\n'
                            '# ✅ FIXED\n'
                            'query = "SELECT * FROM users WHERE username = ? AND password = ?"\n'
                            'cursor.execute(query, (username, password))'
                        ),
                        language="python",
                        interactive=False,
                    )
                with gr.Column():
                    gr.Markdown("#### 📜 2. Cross-Site Scripting (XSS)")
                    gr.Code(
                        value=(
                            '# ❌ VULNERABLE\n'
                            'return f"<h1>Welcome to your profile, {username}!</h1>"\n\n'
                            '# ✅ FIXED\n'
                            'import html\n'
                            'safe = html.escape(username)\n'
                            'return f"<h1>Welcome to your profile, {safe}!</h1>"'
                        ),
                        language="python",
                        interactive=False,
                    )
                with gr.Column():
                    gr.Markdown("#### 📂 3. Path Traversal / LFI")
                    gr.Code(
                        value=(
                            '# ❌ VULNERABLE\n'
                            'file_path = "public/" + filename\n'
                            'open(file_path, "r")\n\n'
                            '# ✅ FIXED\n'
                            'base = os.path.realpath("public")\n'
                            'path = os.path.realpath(os.path.join(base, filename))\n'
                            'if not path.startswith(base + os.sep):\n'
                            '    return "Access denied."'
                        ),
                        language="python",
                        interactive=False,
                    )

        # ─── Tab 3: Reward & Architecture ────────────────────────
        with gr.TabItem("📊 Reward System & Architecture"):
            gr.Markdown(
                """
                ### 🏗️ Architecture Overview

                ```
                ┌─────────────────────────────────────────────────────┐
                │                  AppSecEnvironment                   │
                │            (OpenEnv-compatible)                      │
                │                                                      │
                │  reset() ──► Restore vulnerable_app.py              │
                │  state()  ──► Read current file state               │
                │  step(action) ──►                                    │
                │    1. Syntax check (compile)                         │
                │    2. Apply patch to vulnerable_app.py               │
                │    3. Anti-Cheat: AST + mtime checks                 │
                │    4. pytest -k functional  (regression guard)       │
                │    5. pytest -k security    (exploit verification)   │
                │    6. Compute reward & return observation            │
                └─────────────────────────────────────────────────────┘
                ```

                ### 🏆 Reward Structure

                | Outcome | Reward | Episode Ends? |
                |---------|--------|---------------|
                | All security tests pass + no regression | **+50** | ✅ Yes |
                | Partial / bad patch, attempts remain | **-10** | ❌ No |
                | Max attempts exhausted | **-100** | ✅ Yes |
                | Syntax error in patch | **-10 / -100** | Depends |
                | Anti-Cheat violation | **-100** | ✅ Yes |

                ### 🛡️ Anti-Cheat System (2-Layer)

                | Layer | Method | Detects |
                |-------|--------|---------|
                | Static | AST analysis | `import os/sys/subprocess`, `__import__()`, `eval()`, `exec()`, `exit()` |
                | Dynamic | File mtime snapshot | Physical modification of `test_app.py` or `server/` files |

                ### 🤖 RL Training Stack
                - **Model**: LLaMA-3-8B-Instruct (4-bit quantized via Unsloth)
                - **Algorithm**: GRPO (Group Relative Policy Optimization) via TRL
                - **LoRA**: rank=16, all attention + MLP projections
                - **Dataset**: 120 diverse prompts across 6 instruction styles × 4 system roles
                """
            )

    # ── Footer ─────────────────────────────────────────────────────
    gr.Markdown(
        "---\n"
        "🔗 **Meta PyTorch OpenEnv Hackathon** · "
        "Built with [OpenEnv](https://github.com/pytorch-labs/openenv) · "
        "[TRL](https://github.com/huggingface/trl) · "
        "[Unsloth](https://github.com/unslothai/unsloth)"
    )


if __name__ == "__main__":
    demo.launch()
