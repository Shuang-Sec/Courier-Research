#!/usr/bin/env python3
import argparse, base64, hashlib, http.client, json, ssl, sys, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path

HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailers","transfer-encoding","upgrade"}
PREVIEW_N = 64

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cdn-forward-lab/0.1"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self._forward()
    def do_POST(self):
        self._forward()

    def _forward(self):
        length = int(self.headers.get('Content-Length') or '0')
        body = self.rfile.read(length) if length else b''
        headers = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP or lk == 'content-length':
                continue
            headers[k] = v
        incoming_host = self.headers.get('Host', '')
        if incoming_host:
            headers['X-Forwarded-Host'] = incoming_host
            headers['Host'] = self.server.origin_host_header or incoming_host
        prior_xff = self.headers.get('X-Forwarded-For', '').strip()
        client_ip = self.client_address[0]
        headers['X-Forwarded-For'] = (prior_xff + ', ' + client_ip).strip(', ') if prior_xff else client_ip
        headers['X-Forwarded-Proto'] = 'https'
        start = time.time()
        status = 502
        reason = 'Bad Gateway'
        resp_data = b''
        resp_headers = []
        err = ''
        try:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(self.server.origin_host, self.server.origin_port, context=ctx, timeout=20)
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            status, reason = resp.status, resp.reason
            resp_data = resp.read()
            resp_headers = resp.getheaders()
            conn.close()
        except Exception as exc:
            err = repr(exc)
            resp_data = b'bad gateway'
        self.send_response(status, reason)
        sent_ct = False
        for k, v in resp_headers:
            lk = k.lower()
            if lk in HOP or lk in {'content-length','server','date'}:
                continue
            if lk == 'content-type':
                sent_ct = True
            self.send_header(k, v)
        if not sent_ct:
            self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(resp_data)))
        self.send_header('Via', 'cdn-forward-lab')
        self.end_headers()
        self.wfile.write(resp_data)
        entry = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            'client': client_ip,
            'method': self.command,
            'path': self.path,
            'host': incoming_host,
            'origin_host': headers.get('Host', ''),
            'user_agent': self.headers.get('User-Agent',''),
            'x_beacon_id': self.headers.get('X-Beacon-Id', ''),
            'x_beacon_id_len': len(self.headers.get('X-Beacon-Id', '')),
            'xff_out': headers.get('X-Forwarded-For',''),
            'body_len': len(body),
            'body_sha256': hashlib.sha256(body).hexdigest() if body else '',
            'body_preview_b64': base64.b64encode(body[:PREVIEW_N]).decode() if body else '',
            'status': status,
            'resp_len': len(resp_data),
            'resp_sha256': hashlib.sha256(resp_data).hexdigest() if resp_data else '',
            'resp_preview_b64': base64.b64encode(resp_data[:PREVIEW_N]).decode() if resp_data else '',
            'elapsed_ms': int((time.time()-start)*1000),
            'error': err,
        }
        with self.server.log_path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

class Server(ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self):
        while True:
            try:
                return self.socket.accept()
            except Exception as exc:
                print(json.dumps({
                    'event': 'accept_ignored',
                    'error': repr(exc),
                }, ensure_ascii=False), file=sys.stderr, flush=True)
                continue

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--listen-host', default='0.0.0.0')
    ap.add_argument('--listen-port', type=int, default=9443)
    ap.add_argument('--origin-host', default='127.0.0.1')
    ap.add_argument('--origin-port', type=int, default=8444)
    ap.add_argument('--origin-host-header', default='',
                    help='optional Host header sent to the origin; incoming Host is logged and kept in X-Forwarded-Host')
    ap.add_argument('--cert', required=True)
    ap.add_argument('--key', required=True)
    ap.add_argument('--log', required=True)
    args = ap.parse_args()
    Path(args.log).parent.mkdir(parents=True, exist_ok=True)
    srv = Server((args.listen_host, args.listen_port), Handler)
    srv.origin_host = args.origin_host
    srv.origin_port = args.origin_port
    srv.origin_host_header = args.origin_host_header.strip()
    srv.log_path = Path(args.log)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(json.dumps({'event':'proxy_start','listen':f'{args.listen_host}:{args.listen_port}','origin':f'{args.origin_host}:{args.origin_port}','log':args.log}, ensure_ascii=False), flush=True)
    srv.serve_forever()
