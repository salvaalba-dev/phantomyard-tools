"""Disposable visual QA workspace. No real credentials, deployments or posts."""
import argparse
from pathlib import Path
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from phantomblog import core, server, mcp
from fixtures import create


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=8790)
    parser.add_argument('--proposal-demo', action='store_true', help='Seed a clearly synthetic pending bilingual title proposal')
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='phantomblog-fixture-') as folder:
        root=Path(folder);create(root,13);core.build(root)
        if args.proposal_demo:
            model, revision = core.load(root)
            model['articles'][0]['en']['title'] = 'Reviewed fixture <img src=x onerror=alert(1)>'
            model['articles'][0]['es']['title'] = 'Prueba de revisión en español'
            mcp.call(root, 'phantomblog_propose', {'revision': revision, 'model': model})
        httpd=server.make_server(root,'synthetic-preview-token-not-a-real-secret',args.port)
        print(f'Fixture dashboard: http://127.0.0.1:{httpd.server_port}/',flush=True)
        print('Login uses the synthetic fixture token documented in tests/preview.py.',flush=True)
        try:httpd.serve_forever()
        except KeyboardInterrupt:pass
        finally:httpd.server_close()


if __name__=='__main__':main()
