import threading

from flask import Flask, jsonify, render_template_string
from werkzeug.serving import make_server


PAGE = """
<!doctype html>
<html><head><title>TCP Tarpit</title><meta name="viewport" content="width=device-width">
<style>
body {
  background:#111827;
  color:#e5e7eb;
  font:16px system-ui;
  max-width:1100px;
  margin:32px auto;
  padding:0 18px;
}
h1 { color:#67e8f9; }
.cards { display:flex; flex-wrap:wrap; gap:12px; }
.card { background:#1f2937; border-radius:8px; padding:16px; min-width:130px; }
.n { font-size:28px; font-weight:bold; }
.red { color:#f87171; }
.green { color:#4ade80; }
.yellow { color:#facc15; }
table { width:100%; border-collapse:collapse; margin-top:24px; background:#1f2937; }
th,td { padding:10px; text-align:left; border-bottom:1px solid #374151; }
</style></head><body><h1>TCP Tarpit monitor</h1><div id="cards" class="cards"></div>
<table>
  <thead>
    <tr>
      <th>Time</th>
      <th>Source</th>
      <th>Port</th>
      <th>OS</th>
      <th>Classification</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody id="rows"></tbody>
</table>
<script>
async function refresh() {
  let d = await (await fetch('/api/status')).json();
  document.getElementById('cards').innerHTML = [
    `<div class="card"><div>Total</div><div class="n">${d.stats.total_connections}</div></div>`,
    `<div class="card red"><div>Scanners</div>` +
      `<div class="n">${d.stats.scanner_connections}</div></div>`,
    `<div class="card green"><div>Normal</div>` +
      `<div class="n">${d.stats.normal_connections}</div></div>`,
    `<div class="card yellow"><div>Dribbles</div><div class="n">${d.active_dribbles}</div></div>`
  ].join('');
  document.getElementById('rows').innerHTML = d.connections.map(x => {
    let className = x.classification === 'scanner' ? 'red' : 'green';
    return `<tr><td>${x.timestamp}</td><td>${x.source_ip}:${x.source_port}</td>` +
      `<td>${x.destination_port}</td><td>${x.spoofed_os}</td>` +
      `<td class="${className}">${x.classification}</td><td>${x.status}</td></tr>`;
  }).join('');
} refresh(); setInterval(refresh, 1000);
</script></body></html>
"""


class WebDashboard:
    def __init__(self, database, dribbler, host, port):
        self.database = database
        self.dribbler = dribbler
        self.app = Flask(__name__)
        self.server = make_server(host, port, self.app, threaded=True)
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            name="web-dashboard",
            daemon=True,
        )
        self._routes()

    def _routes(self):
        @self.app.get("/")
        def index():
            return render_template_string(PAGE)

        @self.app.get("/api/status")
        def status():
            return jsonify({
                "stats": self.database.get_stats(),
                "active_dribbles": self.dribbler.active_count(),
                "connections": self.database.get_recent_connections(),
            })

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
