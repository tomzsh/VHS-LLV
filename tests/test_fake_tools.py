from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"


class FakeToolIntegrationTests(unittest.TestCase):
    def test_scanner_dag_and_scope_filters(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            engagement = base / "engagement"
            engagement.mkdir()
            (engagement / "engagement.json").write_text(
                json.dumps(
                    {
                        "engagement_id": "fake-tools",
                        "authorization_status": "confirmed",
                        "permission_mode": "ACTIVE_SAFE",
                        "testing_window": "2020-01-01T00:00:00Z..2099-12-31T23:59:59Z",
                        "allowed_assets": ["example.com", "*.example.com"],
                        "excluded_assets": [],
                        "allowed_methods": ["automated_scanning"],
                        "prohibited_methods": [],
                    }
                ),
                encoding="utf-8",
            )
            (engagement / "state.json").write_text(
                json.dumps({"phases": {"P0": {"status": "completed"}}}),
                encoding="utf-8",
            )

            fakebin = base / "bin"
            fakebin.mkdir()
            fake_scripts = {
                "subfinder": "#!/usr/bin/env bash\nprintf 'api.example.com\\nevil.test\\n'\n",
                "dnsx": "#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do [[ \"$1\" == \"-l\" ]] && { cat \"$2\"; exit 0; }; shift; done\n",
                "httpx": """#!/usr/bin/env python3
import json, sys
path = sys.argv[sys.argv.index('-l') + 1]
for host in open(path, encoding='utf-8'):
    host = host.strip()
    if host:
        print(json.dumps({'url': 'https://' + host, 'status_code': 200}))
""",
                "gau": "#!/usr/bin/env bash\nprintf 'https://api.example.com/a?x=1\\nhttps://evil.test/out\\n'\n",
                "katana": "#!/usr/bin/env bash\nprintf 'https://api.example.com/search?q=1\\nhttps://evil.test/x?a=1\\n'\n",
                "uro": "#!/usr/bin/env bash\nwhile [[ $# -gt 0 ]]; do [[ \"$1\" == \"-i\" ]] && { cat \"$2\"; exit 0; }; shift; done\n",
                "arjun": """#!/usr/bin/env python3
import json, sys
path = sys.argv[sys.argv.index('-oJ') + 1]
open(path, 'w', encoding='utf-8').write(json.dumps({'results': []}))
""",
                "nuclei": """#!/usr/bin/env python3
import json, sys
path = sys.argv[sys.argv.index('-o') + 1]
finding = {'template-id': 'fake', 'matched-at': 'https://api.example.com/search?q=1', 'info': {'severity': 'high', 'name': 'Fake'}}
open(path, 'w', encoding='utf-8').write(json.dumps(finding) + '\\n')
""",
                "dalfox": """#!/usr/bin/env python3
import sys
path = sys.argv[sys.argv.index('--output') + 1]
open(path, 'w', encoding='utf-8').write('fake-poc\n')
""",
                # Stubs for tools that exist on a fully-provisioned host. Without
                # these, PATH falls through to the real binaries (waymore,
                # hakrawler, naabu, ffuf) which hit the network and hang the test.
                "waymore": "#!/usr/bin/env bash\nexit 0\n",
                "hakrawler": "#!/usr/bin/env bash\nexit 0\n",
                "naabu": "#!/usr/bin/env bash\nexit 0\n",
                "ffuf": "#!/usr/bin/env bash\nexit 0\n",
                "amass": "#!/usr/bin/env bash\nexit 0\n",
                "assetfinder": "#!/usr/bin/env bash\nexit 0\n",
                "curl": "#!/usr/bin/env bash\nprintf '404 12'\n",
            }
            for name, body in fake_scripts.items():
                path = fakebin / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)

            out = base / "run"
            env = {
                **os.environ,
                "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
                # Keep this integration test offline even on hosts that have a
                # real crawl4ai venv configured.
                "VHS_CRAWL4AI_PYTHON": str(base / "missing-crawl4ai-python"),
            }
            process = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "vulnhunter_orchestrator.py"),
                    "example.com",
                    "--engagement",
                    str(engagement),
                    "--profile",
                    "scanner-safe",
                    "--out",
                    str(out),
                    "--parallel",
                    "--rate-scan",
                    "7",
                    "--research-header",
                    "X-HackerOne-Research: test-researcher",
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                env=env,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            scoped_urls = (out / "agents" / "crawl" / "urls_all.txt").read_text(encoding="utf-8")
            self.assertIn("api.example.com", scoped_urls)
            self.assertNotIn("evil.test", scoped_urls)

            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            manifest_text = json.dumps(manifest)
            self.assertNotIn("test-researcher", manifest_text)
            httpx_steps = [row for row in manifest["steps"] if row["tool"] == "httpx"]
            self.assertIn("-H", httpx_steps[0]["command"])
            self.assertIn("<redacted>", httpx_steps[0]["command"])
            nuclei_steps = [row for row in manifest["steps"] if row["tool"] == "nuclei"]
            self.assertEqual(len(nuclei_steps), 1)
            self.assertIn("7", nuclei_steps[0]["command"])
            tools = [row["tool"] for row in manifest["steps"]]
            self.assertLess(tools.index("scope-guard-normalized-urls"), tools.index("dalfox"))
            crawl4ai_steps = [row for row in manifest["steps"] if row["tool"] == "crawl4ai"]
            self.assertEqual(crawl4ai_steps[0]["status"], "skipped")
            config = json.loads((out / "run-config.json").read_text(encoding="utf-8"))
            self.assertEqual(config["arguments"]["research_header"], "<redacted>")
            self.assertTrue((out / "agents" / "recon" / "baselines.json").exists())
            self.assertTrue((out / "agents" / "scan" / "nuclei.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
