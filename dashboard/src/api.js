// Thin fetch wrapper that surfaces the {error, detail} envelope from
// ml_engine/main.py as a real Error so React Query renders it consistently.

async function request(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  })
  const text = await res.text()
  let data = null
  if (text) {
    try { data = JSON.parse(text) } catch { data = { raw: text } }
  }
  if (!res.ok) {
    const detail = (data && (data.detail || data.error)) || res.statusText
    const err = new Error(detail)
    err.status = res.status
    err.body = data
    throw err
  }
  return data
}

export const api = {
  listRequests: (params = {}) => {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') q.set(k, v)
    }
    return request(`/api/requests?${q.toString()}`)
  },
  getRequest:    (id)        => request(`/api/requests/${id}`),
  explain:       (id)        => request(`/api/explain/${id}`),
  summary:       ()          => request('/api/stats/summary'),
  timeseries:    (hours=24)  => request(`/api/stats/timeseries?hours=${hours}`),
  topIps:        (hours=24)  => request(`/api/stats/top-ips?hours=${hours}&limit=10`),
  attackTypes:   (hours=24)  => request(`/api/stats/attack-types?hours=${hours}`),
  // ip-rules endpoints are mounted at the root (no /api prefix) in main.py.
  // The vite proxy forwards /ip-rules to the backend directly.
  listIpRules:   ()          => request('/ip-rules'),
  createIpRule:  (body)      => request('/ip-rules', { method: 'POST', body: JSON.stringify(body) }),
  deleteIpRule:  (id)        => request(`/ip-rules/${id}`, { method: 'DELETE' }),
  markFalsePositive: (body)  => request('/api/false-positives', { method: 'POST', body: JSON.stringify(body) }),
  triggerRetrain:    ()      => request('/api/retrain', { method: 'POST' }),
  retrainStatus: (jobId)     => request(`/api/retrain/${jobId}/status`),
  retrainHistory:()          => request('/api/retrain/history'),
  benchmark:     ()          => request('/api/model/benchmark'),
  featureImportances: ()     => request('/api/model/feature-importances'),
  redteamSummary:()          => request('/api/redteam/summary'),
}
