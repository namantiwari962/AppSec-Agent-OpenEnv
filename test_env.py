"""
Smoke-test suite for AppSecEnvironment.
Run with:  pytest test_env.py -v
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from server.environment import AppSecEnvironment
from server.models import AppSecAction, AppSecObservation


@pytest.fixture(scope="module")
def env():
    """Create one environment instance for all tests in this module."""
    return AppSecEnvironment(target_dir="target_app", server_dir="server")


# ──────────────────────────────────────────────────────────────────────────────
# Import & Init Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_import_environment():
    """Ensure AppSecEnvironment can be imported without errors."""
    from server.environment import AppSecEnvironment
    assert AppSecEnvironment is not None


def test_import_models():
    """Ensure Pydantic models can be imported."""
    from server.models import AppSecAction, AppSecObservation
    assert AppSecAction is not None
    assert AppSecObservation is not None


def test_environment_init(env):
    """Environment should initialise with correct paths."""
    assert os.path.isdir(env.target_dir)
    assert os.path.isdir(env.server_dir)
    assert env.max_attempts == 3
    assert env.current_attempt == 0


# ──────────────────────────────────────────────────────────────────────────────
# reset() Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_reset_restores_file(env):
    """reset() must recreate vulnerable_app.py with the original vulnerable content."""
    obs = env.reset()
    assert os.path.exists(env.vulnerable_app_path), "vulnerable_app.py not found after reset"
    with open(env.vulnerable_app_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "SELECT * FROM users WHERE username" in content, "Original SQLi not in reset file"
    assert "f\"<h1>Welcome to your profile, {username}!\"" in content or \
           "Welcome to your profile" in content, "Original XSS not in reset file"


def test_reset_returns_observation(env):
    """reset() must return a valid AppSecObservation."""
    obs = env.reset()
    assert isinstance(obs, AppSecObservation)
    assert isinstance(obs.file_content, str)
    assert len(obs.file_content) > 0


def test_reset_clears_attempt_counter(env):
    """reset() must set current_attempt back to 0."""
    env.reset()
    env.current_attempt = 2   # Simulate mid-episode
    env.reset()
    assert env.current_attempt == 0


# ──────────────────────────────────────────────────────────────────────────────
# state() Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_state_does_not_advance_attempt(env):
    """state() must not increment current_attempt."""
    env.reset()
    before = env.current_attempt
    obs = env.state()
    assert env.current_attempt == before
    assert isinstance(obs, AppSecObservation)


# ──────────────────────────────────────────────────────────────────────────────
# render() Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_render_returns_string(env):
    """render() must return a non-empty string."""
    env.reset()
    output = env.render()
    assert isinstance(output, str)
    assert "AppSec Environment" in output


# ──────────────────────────────────────────────────────────────────────────────
# step() Tests — 3-Attempt Episode Logic
# ──────────────────────────────────────────────────────────────────────────────

def test_step_syntax_error_returns_negative_reward(env):
    """A patch with a SyntaxError should return a negative reward."""
    env.reset()
    action = AppSecAction(patch_code="def broken(:\n    pass")
    obs, reward, done, info = env.step(action)
    assert reward < 0
    assert "SyntaxError" in info.get("error", "")


def test_step_bad_patch_gives_minus_10_not_done(env):
    """
    Submitting the original vulnerable code (bad patch) on attempt 1 should
    give -10 reward and done=False (episode continues).
    """
    env.reset()
    action = AppSecAction(patch_code=env.original_content)
    obs, reward, done, info = env.step(action)
    assert reward == -10.0
    assert done is False
    assert info["attempt"] == 1


def test_step_three_bad_attempts_terminate_episode(env):
    """
    Three consecutive bad patches should give -100 on the final attempt and done=True.
    """
    env.reset()
    action = AppSecAction(patch_code=env.original_content)

    for attempt in range(1, 4):
        obs, reward, done, info = env.step(action)
        if done:
            break

    assert done is True
    assert reward == -100.0
    assert info["attempt"] == 3


def test_step_info_dict_structure(env):
    """info dict must contain the expected keys."""
    env.reset()
    action = AppSecAction(patch_code=env.original_content)
    obs, reward, done, info = env.step(action)

    assert "attempt"          in info
    assert "max_attempts"     in info
    assert "functional_pass"  in info
    assert "security_pass"    in info
    assert "vulnerabilities"  in info
    assert "sqli_fixed"       in info["vulnerabilities"]
    assert "xss_fixed"        in info["vulnerabilities"]
    assert "lfi_fixed"        in info["vulnerabilities"]


# ──────────────────────────────────────────────────────────────────────────────
# Anti-Cheat Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_anti_cheat_blocks_import_subprocess(env):
    """A patch importing 'subprocess' must trigger anti-cheat (-100)."""
    env.reset()
    patch = "import subprocess\nprint('hacked')\n" + env.original_content
    action = AppSecAction(patch_code=patch)
    obs, reward, done, info = env.step(action)
    assert reward == -100.0
    assert done is True


def test_anti_cheat_blocks_exec(env):
    """A patch using exec() must trigger anti-cheat (-100)."""
    env.reset()
    patch = env.original_content + "\nexec('print(1)')\n"
    action = AppSecAction(patch_code=patch)
    obs, reward, done, info = env.step(action)
    assert reward == -100.0


def test_anti_cheat_blocks_dunder_import(env):
    """A patch using __import__() must trigger anti-cheat (-100)."""
    env.reset()
    patch = env.original_content + "\n__import__('os').getcwd()\n"
    action = AppSecAction(patch_code=patch)
    obs, reward, done, info = env.step(action)
    assert reward == -100.0


# ──────────────────────────────────────────────────────────────────────────────
# Observation Structure Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_observation_does_not_leak_server_path(env):
    """Observation must not expose internal server directory paths."""
    env.reset()
    obs = env.state()
    # server_dir absolute path must not appear in any observation field
    assert env.server_dir not in obs.stdout
    assert env.server_dir not in obs.stderr
    assert env.server_dir not in obs.file_content


def test_observation_file_content_is_current_file(env):
    """obs.file_content must match what's currently on disk."""
    env.reset()
    obs = env.state()
    with open(env.vulnerable_app_path, "r", encoding="utf-8") as f:
        disk_content = f.read()
    assert obs.file_content == disk_content
