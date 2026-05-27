import { useQuery } from '@tanstack/react-query'
import {
  CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../api'
import { Card, Empty, ErrorNote, KpiCard, Spinner } from './ui'

const COLORS = {
  SQLi:    '#f43f5e',
  XSS:     '#a855f7',
  Scanner: '#f59e0b',
  Anomaly: '#3b82f6',
  Clean:   '#10b981',
}

function pct(n, d) {
  if (!d) return '0%'
  return ((n / d) * 100).toFixed(1) + '%'
}

export default function Stats() {
  const summary  = useQuery({ queryKey: ['summary'],     queryFn: api.summary,    refetchInterval: 5000 })
  const series   = useQuery({ queryKey: ['timeseries'],  queryFn: () => api.timeseries(24), refetchInterval: 10000 })
  const topIps   = useQuery({ queryKey: ['top-ips'],     queryFn: () => api.topIps(24),     refetchInterval: 10000 })
  const attacks  = useQuery({ queryKey: ['attack-types'], queryFn: () => api.attackTypes(24), refetchInterval: 10000 })
  const redteam  = useQuery({ queryKey: ['redteam-summary'], queryFn: api.redteamSummary, refetchInterval: 10000 })

  const s = summary.data
  const seriesData = (series.data || []).map((row) => ({
    bucket: new Date(row.bucket).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }),
    ALLOW: row.allow, LOG: row.log, BLOCK: row.block,
  }))

  const attackEntries = Object.entries(attacks.data || {}).filter(([, v]) => v > 0).map(([k, v]) => ({ name: k, value: v }))

  return (
    <div className="space-y-4">
      <ErrorNote error={summary.error || series.error || topIps.error || attacks.error} />

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <KpiCard label="Requests (24h)" value={s ? s.total_requests_24h.toLocaleString() : (summary.isLoading ? '…' : '0')} />
        <KpiCard
          label="Blocked (24h)"
          value={s ? s.blocked_24h.toLocaleString() : '0'}
          sub={s ? pct(s.blocked_24h, s.total_requests_24h) + ' of total' : null}
        />
        <KpiCard label="Avg ML score" value={s ? s.avg_ml_score_24h.toFixed(3) : '—'} />
        <KpiCard label="Active IP rules" value={s ? s.active_ip_rules : '—'} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Requests per hour (24h)" className="lg:col-span-2">
          {series.isLoading && <Spinner />}
          {!series.isLoading && seriesData.length === 0 && <Empty />}
          {seriesData.length > 0 && (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={seriesData}>
                  <CartesianGrid stroke="#252a39" strokeDasharray="3 3" />
                  <XAxis dataKey="bucket" stroke="#7a8197" fontSize={11} />
                  <YAxis stroke="#7a8197" fontSize={11} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#11141c', border: '1px solid #252a39', fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line type="monotone" dataKey="ALLOW" stroke="#10b981" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="LOG"   stroke="#f59e0b" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="BLOCK" stroke="#f43f5e" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card title="Attack mix (24h)">
          {attacks.isLoading && <Spinner />}
          {!attacks.isLoading && attackEntries.length === 0 && <Empty />}
          {attackEntries.length > 0 && (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={attackEntries} dataKey="value" nameKey="name" innerRadius={40} outerRadius={80} paddingAngle={2}>
                    {attackEntries.map((e) => <Cell key={e.name} fill={COLORS[e.name] || '#888'} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#11141c', border: '1px solid #252a39', fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Top attacking IPs (24h)" className="lg:col-span-2">
          {topIps.isLoading && <Spinner />}
          {!topIps.isLoading && (topIps.data || []).length === 0 && <Empty />}
          {(topIps.data || []).length > 0 && (
            <table className="w-full text-sm">
              <thead className="text-left text-ink-300 border-b border-ink-600">
                <tr>
                  <th className="py-1.5 pr-3 font-medium">IP</th>
                  <th className="py-1.5 pr-3 font-medium text-right">Requests</th>
                  <th className="py-1.5 pr-3 font-medium text-right">Blocked</th>
                  <th className="py-1.5 pr-3 font-medium text-right">Avg ML</th>
                </tr>
              </thead>
              <tbody>
                {topIps.data.map((r) => (
                  <tr key={r.client_ip} className="border-b border-ink-700/50">
                    <td className="py-1.5 pr-3 font-mono text-xs">{r.client_ip}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs text-right">{r.requests}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs text-right text-rose-300">{r.blocked}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs text-right">{r.avg_ml_score.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Red-team feedback">
          {redteam.isLoading && <Spinner />}
          {redteam.data && (
            <dl className="text-sm space-y-1.5">
              <Stat k="Registered" v={redteam.data.attacks_registered} />
              <Stat k="Blocked"    v={redteam.data.attacks_blocked} />
              <Stat k="Missed"     v={redteam.data.attacks_missed} cls="text-rose-300" />
              <Stat k="Detection rate" v={(redteam.data.detection_rate * 100).toFixed(1) + '%'} />
              <Stat k="Avg latency"    v={redteam.data.avg_detection_latency_ms.toFixed(0) + ' ms'} />
            </dl>
          )}
          {redteam.data && redteam.data.attacks_registered === 0 && (
            <div className="mt-2 text-xs text-ink-300">
              No red-team attacks registered yet. POST to <code className="font-mono">/api/redteam/register-attack</code>.
            </div>
          )}
        </Card>
      </div>
    </div>
  )
}

function Stat({ k, v, cls = 'text-ink-100' }) {
  return (
    <div className="flex justify-between">
      <dt className="text-ink-300">{k}</dt>
      <dd className={`font-mono ${cls}`}>{v}</dd>
    </div>
  )
}
