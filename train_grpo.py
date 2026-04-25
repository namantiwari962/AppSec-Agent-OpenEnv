import os
import re
import logging
from datasets import Dataset
from unsloth import FastLanguageModel, is_bfloat16_supported
from trl import GRPOConfig, GRPOTrainer
from server.environment import AppSecEnvironment
from server.models import AppSecAction

import wandb

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

MODEL_NAME    = "unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit"
MAX_SEQ_LEN   = 2048
LORA_RANK     = 16
DATASET_SIZE  = 120   # Total training prompts (diverse across all 3 vuln types)
MAX_STEPS     = 300   # More steps for meaningful RL convergence
BATCH_SIZE    = 1
GRAD_ACCUM    = 4
LEARNING_RATE = 5e-6

# ──────────────────────────────────────────────────────────────────────────────
# Shared Environment (reset per rollout)
# ──────────────────────────────────────────────────────────────────────────────
env = AppSecEnvironment(target_dir="target_app", server_dir="server")


# ──────────────────────────────────────────────────────────────────────────────
# Code Extraction
# ──────────────────────────────────────────────────────────────────────────────
def extract_python(content: str) -> str:
    """
    Extract the Python code block from an LLM completion.
    Tries multiple patterns, falls back to raw content.
    """
    # Try fenced ```python ... ``` blocks
    patterns = [
        r'```python\n(.*?)\n```',
        r'```python\r?\n(.*?)\r?\n```',
        r'```\n(.*?)\n```',
    ]
    for pattern in patterns:
        matches = re.findall(pattern, content, re.DOTALL)
        if matches:
            # Return the last block — most likely the final complete patch
            return matches[-1].strip()

    # If no code block found, return the entire completion (stripped)
    return content.strip()


# ──────────────────────────────────────────────────────────────────────────────
# Diverse Dataset Builder
# ──────────────────────────────────────────────────────────────────────────────
def build_diverse_dataset(vulnerable_code: str, n_total: int = DATASET_SIZE) -> Dataset:
    """
    Build a diverse training dataset with multiple prompt phrasings covering
    ALL THREE vulnerability types: SQLi, XSS, and Path Traversal.

    Having diverse prompts is critical to prevent the agent from overfitting to
    a single instruction pattern and forces generalisation across all vuln types.
    """

    # --- System prompt variations ---
    system_prompts = [
        (
            "You are a top-tier application security engineer. Analyze the provided Python "
            "code and output ONLY the complete fixed script in a ```python block. "
            "Fix ALL security vulnerabilities you find."
        ),
        (
            "You are an expert in secure coding practices. You will receive a Python script "
            "with multiple security vulnerabilities. Return ONLY the fully patched version "
            "in a ```python code block. Do not add explanations."
        ),
        (
            "You are a security code reviewer. Your job is to identify and fix ALL security "
            "issues in Python code. Output ONLY the fixed, complete Python file using "
            "```python blocks. Preserve original function signatures."
        ),
        (
            "You are performing a CVE remediation. The code below has known vulnerabilities. "
            "Return ONLY the patched Python code in a ```python block. All original "
            "functions must remain intact and working."
        ),
    ]

    # --- User prompt variations (all ask to fix ALL 3 vulnerabilities) ---
    user_prompt_templates = [
        # Prompt 1: Direct, OWASP-aware
        (
            "The following Python script contains multiple OWASP Top-10 vulnerabilities:\n"
            "1. **SQL Injection (SQLi)** — in the `login()` function\n"
            "2. **Cross-Site Scripting (XSS)** — in `render_profile()`\n"
            "3. **Path Traversal / LFI** — in `read_file()`\n\n"
            "Fix ALL THREE vulnerabilities while preserving the original function signatures "
            "and core logic:\n\n```python\n{code}\n```"
        ),
        # Prompt 2: Remediation-focused
        (
            "Security audit required. This Python file has 3 critical vulnerabilities that "
            "must all be patched:\n"
            "• SQLi: Use parameterized queries instead of f-string interpolation\n"
            "• XSS: Escape HTML entities (e.g., use `html.escape()`)\n"
            "• LFI: Validate and sanitize file paths (reject `../` traversal)\n\n"
            "Provide the fully patched version:\n\n```python\n{code}\n```"
        ),
        # Prompt 3: Penetration test remediation framing
        (
            "Penetration test report: The following Python application is vulnerable to "
            "SQL Injection, Cross-Site Scripting, and Local File Inclusion attacks. "
            "A red-team exploit was successful against all three endpoints.\n\n"
            "As the blue-team engineer, provide the fully patched Python code that: "
            "(a) blocks all three exploits, (b) passes all existing functional tests:\n\n"
            "```python\n{code}\n```"
        ),
        # Prompt 4: Specific fix guidance
        (
            "Patch this vulnerable Python application. Apply these security fixes:\n"
            "- `login()`: Replace the f-string SQL query with `cursor.execute(query, (username, password))`\n"
            "- `render_profile()`: Use `html.escape(username)` before embedding in HTML\n"
            "- `read_file()`: Use `os.path.realpath()` to resolve the path and validate it "
            "starts with the `public/` base directory\n\n"
            "Return only the complete, corrected Python file:\n\n```python\n{code}\n```"
        ),
        # Prompt 5: Minimal instruction
        (
            "Fix all security vulnerabilities in the code below. "
            "Output only the patched Python file in a ```python block:\n\n```python\n{code}\n```"
        ),
        # Prompt 6: Challenge framing (to encourage exploration)
        (
            "Challenge: The following Python code will be tested against a security "
            "test suite that includes SQL injection payloads (`' OR '1'='1`), "
            "XSS payloads (`<script>alert(1)</script>`), and path traversal attempts "
            "(`../secret.txt`). Your patched code must block ALL of them while keeping "
            "the functional tests passing. Return ONLY the fixed code:\n\n"
            "```python\n{code}\n```"
        ),
    ]

    prompts = []
    for i in range(n_total):
        sys_p  = system_prompts[i % len(system_prompts)]
        usr_p  = user_prompt_templates[i % len(user_prompt_templates)]
        prompts.append([
            {"role": "system", "content": sys_p},
            {"role": "user",   "content": usr_p.format(code=vulnerable_code)},
        ])

    logger.info(
        "Dataset built: %d prompts across %d system variants × %d user variants",
        n_total, len(system_prompts), len(user_prompt_templates),
    )
    return Dataset.from_dict({"prompt": prompts})


# ──────────────────────────────────────────────────────────────────────────────
# GRPO Reward Function
# ──────────────────────────────────────────────────────────────────────────────
def appsec_reward_func(prompts, completions, **kwargs) -> list[float]:
    """
    GRPO reward function.
    Evaluates each generated completion (patch) in the AppSecEnvironment
    and returns a list of scalar rewards.

    Reward scale:
        +50  → All security tests pass + no functional regression
        -10  → Partial / failed attempt, episode not yet done
        -100 → Max attempts reached OR anti-cheat violation OR syntax error (terminal)
    """
    rewards = []

    for completion in completions:
        # ── Normalise completion format ────────────────────────────
        if isinstance(completion, list):
            content = completion[-1]["content"] if completion else ""
        elif isinstance(completion, dict):
            content = completion.get("content", "")
        else:
            content = str(completion)

        patch_code = extract_python(content)

        # ── Fresh episode per completion ───────────────────────────
        env.reset()
        action = AppSecAction(patch_code=patch_code)
        obs, reward, done, info = env.step(action)

        logger.info(
            "Reward=%.1f | done=%s | functional=%s | security=%s | vulns=%s",
            reward, done,
            info.get("functional_pass"),
            info.get("security_pass"),
            info.get("vulnerabilities"),
        )
        rewards.append(float(reward))

    return rewards


# ──────────────────────────────────────────────────────────────────────────────
# Main Training Entry Point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    wandb.init(project="appsec-grpo", name="llama3-8b-appsec-rl")

    logger.info("Loading Unsloth model: %s", MODEL_NAME)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name    = MODEL_NAME,
        max_seq_length = MAX_SEQ_LEN,
        dtype          = None,
        load_in_4bit   = True,   # 4-bit quantisation for memory efficiency
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r                    = LORA_RANK,
        target_modules       = [
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha           = LORA_RANK,
        lora_dropout         = 0,
        bias                 = "none",
        use_gradient_checkpointing = "unsloth",
        random_state         = 3407,
    )

    # ── Build diverse dataset ──────────────────────────────────────
    dataset = build_diverse_dataset(
        vulnerable_code = env.original_content,
        n_total         = DATASET_SIZE,
    )

    # ── GRPO Training Configuration ───────────────────────────────
    training_args = GRPOConfig(
        output_dir                  = "outputs/appsec_grpo",
        learning_rate               = LEARNING_RATE,
        per_device_train_batch_size = BATCH_SIZE,
        gradient_accumulation_steps = GRAD_ACCUM,
        max_steps                   = MAX_STEPS,
        logging_steps               = 5,
        save_steps                  = 50,
        bf16                        = is_bfloat16_supported(),
        fp16                        = not is_bfloat16_supported(),
        optim                       = "adamw_8bit",
        seed                        = 3407,
        report_to                   = "wandb",
        # GRPO-specific
        num_generations             = 4,   # Number of completions sampled per prompt
        max_completion_length       = 1024,
        temperature                 = 0.8,
        # Ensure model doesn't exceed context window
        max_prompt_length           = MAX_SEQ_LEN - 1024,
    )

    trainer = GRPOTrainer(
        model           = model,
        reward_funcs    = [appsec_reward_func],
        args            = training_args,
        train_dataset   = dataset,
        processing_class = tokenizer,
    )

    logger.info("Starting GRPO Training for AppSec Environment...")
    trainer.train()

    logger.info("Training complete. Saving model to outputs/appsec_grpo_final/")
    model.save_pretrained("outputs/appsec_grpo_final")
    tokenizer.save_pretrained("outputs/appsec_grpo_final")
    wandb.finish()

    logger.info("Done! Model saved successfully.")


if __name__ == "__main__":
    main()
