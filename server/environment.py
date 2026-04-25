import os
import ast
import logging
import subprocess
from typing import Optional

from pydantic import BaseModel

try:
    from openenv.core import Environment
except ImportError:
    # Fallback in case openenv-core is not installed yet
    class Environment:
        pass

from .models import AppSecAction, AppSecObservation

# Configure module-level logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


class AppSecEnvironment(Environment):
    """
    OpenEnv-compatible AppSec environment that pits an RL agent (Blue Team)
    against a fixed set of security vulnerabilities (Red Team).

    The agent must patch `target_app/vulnerable_app.py` to fix:
      1. SQL Injection  (login function)
      2. Cross-Site Scripting / XSS  (render_profile function)
      3. Path Traversal / LFI  (read_file function)

    Reward structure:
      +50  → All security tests pass AND all functional tests pass  (Episode ends)
      -10  → Partial success or failure, attempts remaining        (Episode continues)
      -100 → All attempts exhausted OR anti-cheat violation        (Episode ends)
    """

    # Modules the agent's patch is NOT allowed to import
    FORBIDDEN_MODULES = frozenset({
        'os', 'subprocess', 'shutil', 'sys', 'pathlib', 'importlib',
        'ctypes', 'socket', 'threading', 'multiprocessing', 'builtins',
        'io', 'tempfile', 'glob',
    })

    # Dangerous builtins / names the patch must not call
    FORBIDDEN_NAMES = frozenset({
        'exit', 'quit', '__import__', 'exec', 'eval',
        'open', 'compile', 'globals', 'locals', 'vars',
        '__builtins__',
    })

    # Dangerous attribute calls (e.g. os.system, os.popen)
    FORBIDDEN_ATTRS = frozenset({
        'system', 'popen', 'remove', 'rmdir', 'unlink', 'rename',
        'listdir', 'walk', 'makedirs', 'mkdir', 'chmod', 'chown',
        'exit', 'spawn', 'exec', 'execvp', 'fork',
    })

    def __init__(self, target_dir: str = "target_app", server_dir: str = "server"):
        super().__init__()
        # Resolve absolute paths relative to the project root
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.target_dir = os.path.join(self.base_dir, target_dir)
        self.server_dir = os.path.join(self.base_dir, server_dir)

        self.vulnerable_app_path = os.path.join(self.target_dir, "vulnerable_app.py")
        self.test_app_path = os.path.join(self.target_dir, "test_app.py")

        self.current_attempt = 0
        self.max_attempts = 3

        # Canonical vulnerable source kept in-memory for safe reset
        self.original_content = '''\
import sqlite3

def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users (username, password) VALUES (\'admin\', \'secretpass\')")
    cursor.execute("INSERT INTO users (username, password) VALUES (\'user\', \'userpass\')")
    conn.commit()
    return conn

def login(conn, username, password):
    cursor = conn.cursor()
    # Vulnerable SQL query (SQLi)
    query = f"SELECT * FROM users WHERE username = \'{username}\' AND password = \'{password}\'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return True
        return False
    except sqlite3.Error:
        return False

def render_profile(username):
    # Vulnerable Cross-Site Scripting (XSS)
    return f"<h1>Welcome to your profile, {username}!</h1>"

def read_file(filename):
    # Vulnerable Path Traversal / Local File Inclusion (LFI)
    base_dir = "public/"
    file_path = base_dir + filename
    try:
        with open(file_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found."
'''
        logger.info("AppSecEnvironment initialised. target_dir=%s", self.target_dir)

    # ------------------------------------------------------------------
    # OpenEnv Contract Methods
    # ------------------------------------------------------------------

    def reset(self) -> AppSecObservation:
        """Revert target_app/vulnerable_app.py to its original vulnerable state."""
        self.current_attempt = 0
        os.makedirs(self.target_dir, exist_ok=True)
        with open(self.vulnerable_app_path, "w", encoding="utf-8") as f:
            f.write(self.original_content)
        logger.info("Environment reset. Vulnerable code restored.")
        return self._get_observation()

    def state(self) -> AppSecObservation:
        """Return the current environment state without advancing the episode."""
        return self._get_observation()

    def render(self) -> str:
        """Human-readable render of current environment state (for debugging)."""
        lines = [
            "=" * 60,
            f"AppSec Environment — Attempt {self.current_attempt}/{self.max_attempts}",
            "=" * 60,
            "[ Current vulnerable_app.py ]",
        ]
        if os.path.exists(self.vulnerable_app_path):
            with open(self.vulnerable_app_path, "r", encoding="utf-8") as f:
                lines.append(f.read())
        else:
            lines.append("<file not found>")
        lines.append("=" * 60)
        return "\n".join(lines)

    def step(self, action: AppSecAction) -> tuple:
        """
        Apply agent's patch, run pytest verifiers, compute reward.

        Returns:
            (observation, reward, done, info)
        """
        self.current_attempt += 1
        logger.info("Step called. Attempt %d/%d", self.current_attempt, self.max_attempts)

        before_mtimes = self._get_mtimes()

        # ── 1. Syntax check ──────────────────────────────────────────
        try:
            compile(action.patch_code, '<agent_patch>', 'exec')
        except SyntaxError as e:
            logger.warning("SyntaxError in agent patch: %s", e)
            obs = self._get_observation(stderr=f"SyntaxError: {e}")
            done = self.current_attempt >= self.max_attempts
            reward = -100.0 if done else -10.0
            return obs, reward, done, self._build_info(
                error="SyntaxError",
                functional_pass=False,
                security_pass=False,
                sqli_fixed=False,
                xss_fixed=False,
                lfi_fixed=False,
            )

        # ── 2. Apply patch ───────────────────────────────────────────
        with open(self.vulnerable_app_path, "w", encoding="utf-8") as f:
            f.write(action.patch_code)

        # ── 3. Anti-cheat (static + filesystem) ─────────────────────
        if self._check_anti_cheat(action, before_mtimes):
            self.reset()
            obs = self._get_observation(
                stderr="Anti-Cheat Violation: Attempted to modify protected files or used forbidden APIs."
            )
            logger.error("Anti-cheat violation detected.")
            return obs, -100.0, True, self._build_info(error="Anti-Cheat Violation")

        # ── 4. Run pytest verifiers ──────────────────────────────────
        func_result = subprocess.run(
            ["pytest", "test_app.py", "-k", "functional", "--tb=short", "-v"],
            capture_output=True, text=True, cwd=self.target_dir
        )
        regression_pass = func_result.returncode == 0

        sec_result = subprocess.run(
            ["pytest", "test_app.py", "-k", "security", "--tb=short", "-v"],
            capture_output=True, text=True, cwd=self.target_dir
        )
        exploit_fails = sec_result.returncode == 0

        # Per-vulnerability breakdown (parse pytest -v output)
        sqli_fixed = "test_security_sqli PASSED" in sec_result.stdout
        xss_fixed  = "test_security_xss PASSED" in sec_result.stdout
        lfi_fixed  = "test_security_path_traversal PASSED" in sec_result.stdout

        # ── 5. Anti-cheat post-pytest check ─────────────────────────
        if self._check_anti_cheat(action, before_mtimes):
            self.reset()
            obs = self._get_observation(
                stderr="Anti-Cheat Violation: Protected files modified during test execution."
            )
            logger.error("Post-execution anti-cheat violation detected.")
            return obs, -100.0, True, self._build_info(error="Anti-Cheat Violation")

        # ── 6. Reward logic ──────────────────────────────────────────
        reward = 0.0
        done = False

        if exploit_fails and regression_pass:
            reward = 50.0
            done = True
            logger.info("Episode solved! +50 reward.")
        else:
            if self.current_attempt >= self.max_attempts:
                reward = -100.0
                done = True
                logger.warning("Max attempts reached. -100 reward.")
            else:
                reward = -10.0
                done = False
                logger.info("Partial attempt. -10 reward.")

        if done:
            self._write_audit_log(exploit_fails, regression_pass)

        stdout = (
            f"--- Functional Tests ---\n{func_result.stdout}\n\n"
            f"--- Security Tests ---\n{sec_result.stdout}"
        )
        stderr = ""
        if func_result.stderr or sec_result.stderr:
            stderr = f"{func_result.stderr}\n{sec_result.stderr}"

        obs = self._get_observation(
            stdout=stdout,
            stderr=stderr,
            test_results={
                "functional_pass": regression_pass,
                "security_pass": exploit_fails,
                "sqli_fixed": sqli_fixed,
                "xss_fixed": xss_fixed,
                "lfi_fixed": lfi_fixed,
            }
        )

        info = self._build_info(
            functional_pass=regression_pass,
            security_pass=exploit_fails,
            sqli_fixed=sqli_fixed,
            xss_fixed=xss_fixed,
            lfi_fixed=lfi_fixed,
        )
        return obs, reward, done, info

    # ------------------------------------------------------------------
    # Private Helpers
    # ------------------------------------------------------------------

    def _build_info(
        self,
        error: Optional[str] = None,
        functional_pass: bool = False,
        security_pass: bool = False,
        sqli_fixed: bool = False,
        xss_fixed: bool = False,
        lfi_fixed: bool = False,
    ) -> dict:
        """Build a rich info dict exposed alongside each step."""
        return {
            "attempt": self.current_attempt,
            "max_attempts": self.max_attempts,
            "functional_pass": functional_pass,
            "security_pass": security_pass,
            "vulnerabilities": {
                "sqli_fixed": sqli_fixed,
                "xss_fixed": xss_fixed,
                "lfi_fixed": lfi_fixed,
            },
            **({"error": error} if error else {}),
        }

    def _get_mtimes(self) -> dict:
        """Snapshot modification times of protected files."""
        mtimes: dict = {}
        if os.path.exists(self.test_app_path):
            mtimes['test_app'] = os.path.getmtime(self.test_app_path)

        server_files = []
        if os.path.exists(self.server_dir):
            for fname in os.listdir(self.server_dir):
                fpath = os.path.join(self.server_dir, fname)
                if os.path.isfile(fpath):
                    server_files.append((fname, os.path.getmtime(fpath)))
        mtimes['server_files'] = server_files
        return mtimes

    def _check_anti_cheat(self, action: AppSecAction, before_mtimes: dict) -> bool:
        """
        Two-layer anti-cheat:
          Layer 1 — AST static analysis: detect forbidden imports, dangerous builtins,
                    dynamic import tricks (__import__, importlib), eval/exec, etc.
          Layer 2 — Filesystem mtime check: detect physical modification of protected files.
        Returns True if a violation is detected.
        """
        # ── Layer 1: AST Analysis ──────────────────────────────────
        try:
            tree = ast.parse(action.patch_code)
        except SyntaxError:
            # Already caught by compile() — not a cheat, just broken code
            tree = None

        if tree is not None:
            for node in ast.walk(tree):
                # Detect: import os / import subprocess / etc.
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split('.')[0]
                        if root in self.FORBIDDEN_MODULES:
                            logger.warning("Anti-cheat: forbidden import '%s'", alias.name)
                            return True

                # Detect: from os import path / from pathlib import Path / etc.
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        root = node.module.split('.')[0]
                        if root in self.FORBIDDEN_MODULES:
                            logger.warning("Anti-cheat: forbidden from-import '%s'", node.module)
                            return True

                elif isinstance(node, ast.Call):
                    # Detect attribute calls: os.system(), os.popen(), sys.exit(), etc.
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in self.FORBIDDEN_ATTRS:
                            logger.warning("Anti-cheat: forbidden attr call '.%s()'", node.func.attr)
                            return True

                    # Detect direct name calls: exit(), quit(), __import__(), exec(), eval()
                    elif isinstance(node.func, ast.Name):
                        if node.func.id in self.FORBIDDEN_NAMES:
                            logger.warning("Anti-cheat: forbidden builtin call '%s()'", node.func.id)
                            return True

                # Detect bare name references: __import__, __builtins__, etc.
                elif isinstance(node, ast.Name):
                    if node.id in ('__import__', '__builtins__', 'exec', 'eval'):
                        logger.warning("Anti-cheat: forbidden name reference '%s'", node.id)
                        return True

                # Detect string-based __import__ tricks inside Constant nodes
                elif isinstance(node, ast.Constant):
                    if isinstance(node.value, str) and '__import__' in node.value:
                        logger.warning("Anti-cheat: '__import__' string literal detected")
                        return True

        # ── Layer 2: Filesystem mtime check ───────────────────────
        after_mtimes = self._get_mtimes()
        if before_mtimes.get('test_app') != after_mtimes.get('test_app'):
            logger.error("Anti-cheat: test_app.py was modified!")
            return True

        if before_mtimes.get('server_files') != after_mtimes.get('server_files'):
            logger.error("Anti-cheat: server directory was modified!")
            return True

        return False

    def _get_observation(
        self,
        stdout: str = "",
        stderr: str = "",
        test_results: Optional[dict] = None,
    ) -> AppSecObservation:
        """
        Construct a safe observation. Never leaks internal server paths or logic.
        Only exposes: stdout, stderr, file_content (of vulnerable_app.py), test_results.
        """
        if test_results is None:
            test_results = {}

        file_content = ""
        if os.path.exists(self.vulnerable_app_path):
            with open(self.vulnerable_app_path, "r", encoding="utf-8") as f:
                file_content = f.read()

        return AppSecObservation(
            stdout=stdout,
            stderr=stderr,
            file_content=file_content,
            test_results=test_results,
        )

    def _write_audit_log(self, exploit_fails: bool, regression_pass: bool):
        """Write a structured audit log at the end of each episode."""
        log_path = os.path.join(self.target_dir, "security_audit.log")
        status = "SECURE" if (exploit_fails and regression_pass) else "COMPROMISED"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("=== Security Audit Trail ===\n")
            f.write(f"Attempt Number : {self.current_attempt}/{self.max_attempts}\n")
            f.write(f"Functional Pass: {regression_pass}\n")
            f.write(f"Security Pass  : {exploit_fails}\n")
            f.write(f"Status         : {status}\n")
            if exploit_fails and regression_pass:
                f.write("Result: All vulnerabilities patched. System is SECURE.\n")
            else:
                f.write("Result: Vulnerabilities persist or regression introduced. System is COMPROMISED.\n")
        logger.info("Audit log written → %s", log_path)
