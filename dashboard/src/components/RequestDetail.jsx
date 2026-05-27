import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BarChart, Bar, XAxis, YAxis, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { api } from '../api'
import { Button, DecisionBadge, Empty, ErrorNote, Spinner, fmtDateTime } from './ui'

export default function RequestDetail({ requestId, onClose }) {
  const queryClient = useQueryClient()
  const [flash, setFlash] = useState(null)

  const reqQ = useQuery({
    queryKey: ['request', requestId],
    queryFn: () => api.getRequest(requestId),
  })
  const explainQ = useQuery({
    queryKey: ['explain', requestId],
    queryFn: () => api.explain(requestId),
    retry: 0,
  })

  const markFp = useMutation({
    mutationFn: () => api.markFalsePositive({ request_log_id: requestId, label: 'FALSE_POSITIVE' }),
    onSuccess: () => {
      setFlash({ kind: 'ok', msg: 'Marked as false positive. Trigger retraining from the Model page to use this feedback.' })
      queryClient.invalidateQueries({ queryKey: ['requests'] })
    },
    onError: (e) => setFlash({ kind: 'err', msg: e.message }),
  })

  const blockIp = useMutation({
    mutationFn: () => api.createIpRule({
      ip_cidr: reqQ.data.client_ip + (reqQ.data.client_ip.includes(':') ? '/128' : '/32'),
      action: 'BLOCK',
      reason: `manual block from request #${requestId}`,
      expires_in_hours: 24,
    }),
    onSuccess: () => {
      setFlash({ kind: 'ok', msg: 'IP blocked for 24 hours.' })
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] })
    },
    onError: (e) => setFlash({ kind: 'err', msg: e.message }),
  })

  // Close on Escape — every modal-y thing should do this.
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const req = reqQ.data
  const explanation = explainQ.data

  const top5 = (explanation?.features || []).slice(0, 5).map((f) => ({
    ...f,
    color: f.shap_value >= 0 ? '#f43f5e' : '#10b981',
  }))

  return (
    <div className="fixed inset-0 z-40 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-ink-800 border border-ink-600 rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-4 border-b border-ink-600 sticky top-0 bg-ink-800 z-10">
          <div>
            <h2 className="text-lg font-semibold text-ink-100">Request #{requestId}</h2>
            {req && <div className="text-xs text-ink-300 mt-0.5">{fmtDateTime(req.timestamp)}</div>}
          </div>
          <div className="flex items-center gap-2">
            {req && <DecisionBadge decision={req.decision} />}
            <Button variant="ghost" onClick={onClose}>✕</Button>
          </div>
        </div>

        <div className="p-4 space-y-4">
          {flash && (
            <div className={`text-sm rounded px-3 py-2 border ${
              flash.kind === 'ok'
                ? 'bg-emerald-900/30 text-emerald-200 border-emerald-700'
                : 'bg-rose-900/30 text-rose-200 border-rose-700'
            }`}>{flash.msg}</div>
          )}

          {reqQ.isLoading && <Spinner />}
          <ErrorNote error={reqQ.error} />

          {req && (
            <>
              <section className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <Kv k="Client IP" v={<span className="font-mono">{req.client_ip}</span>} />
                <Kv k="Method"    v={<span className="font-mono">{req.method}</span>} />
                <Kv k="ML score"  v={req.ml_score?.toFixed(3) ?? '—'} />
                <Kv k="ModSec"    v={req.modsec_score?.toFixed(3) ?? '—'} />
              </section>

              <section>
                <h3 className="text-sm font-semibold text-ink-200 mb-1">URI</h3>
                <pre className="bg-ink-900 border border-ink-600 rounded p-2 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">{req.uri}</pre>
              </section>

              {req.raw_request?.headers && Object.keys(req.raw_request.headers).length > 0 && (
                <section>
                  <h3 className="text-sm font-semibold text-ink-200 mb-1">Headers</h3>
                  <pre className="bg-ink-900 border border-ink-600 rounded p-2 text-xs font-mono overflow-x-auto whitespace-pre-wrap">
                    {Object.entries(req.raw_request.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                  </pre>
                </section>
              )}

              {req.raw_request?.body && (
                <section>
                  <h3 className="text-sm font-semibold text-ink-200 mb-1">Body (preview)</h3>
                  <pre className="bg-ink-900 border border-ink-600 rounded p-2 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all">
                    {req.raw_request.body.slice(0, 2000)}
                  </pre>
                </section>
              )}

              <section>
                <h3 className="text-sm font-semibold text-ink-200 mb-1">
                  SHAP explanation
                  {explanation && (
                    <span className="ml-2 text-xs font-normal text-ink-300">
                      base={explanation.base_value.toFixed(2)} · pred={explanation.prediction.toFixed(3)} · {explanation.elapsed_ms?.toFixed(1)} ms
                    </span>
                  )}
                </h3>
                <ErrorNote error={explainQ.error} />
                {explainQ.isLoading && <Spinner />}
                {top5.length === 0 && !explainQ.isLoading && !explainQ.error && (
                  <Empty message="No explanation available for this request." />
                )}
                {top5.length > 0 && (
                  <div className="h-56 bg-ink-900 border border-ink-600 rounded p-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={top5} layout="vertical" margin={{ left: 100, right: 24 }}>
                        <XAxis type="number" stroke="#7a8197" fontSize={11} />
                        <YAxis dataKey="name" type="category" stroke="#7a8197" fontSize={11} width={140} />
                        <Tooltip
                          contentStyle={{ background: '#11141c', border: '1px solid #252a39', fontSize: 12 }}
                          formatter={(v) => v.toFixed(4)}
                        />
                        <Bar dataKey="shap_value">
                          {top5.map((f, i) => <Cell key={i} fill={f.color} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
                {top5.length > 0 && (
                  <div className="mt-2 text-xs text-ink-300 grid grid-cols-2 gap-1">
                    {top5.map((f) => (
                      <div key={f.name} className="font-mono">
                        <span className="text-ink-200">{f.name}</span>
                        <span className="ml-2">value={f.value.toFixed(2)}</span>
                        <span className={`ml-2 ${f.shap_value >= 0 ? 'text-rose-300' : 'text-emerald-300'}`}>
                          shap={f.shap_value.toFixed(4)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              <section className="flex flex-wrap gap-2 pt-2 border-t border-ink-600">
                <Button
                  variant="primary"
                  onClick={() => markFp.mutate()}
                  disabled={markFp.isPending}
                >
                  {markFp.isPending ? <Spinner /> : null} Mark as False Positive
                </Button>
                <Button
                  variant="danger"
                  onClick={() => blockIp.mutate()}
                  disabled={blockIp.isPending || !req.client_ip}
                >
                  {blockIp.isPending ? <Spinner /> : null} Block this IP (24h)
                </Button>
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function Kv({ k, v }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-ink-300">{k}</div>
      <div className="text-ink-100 mt-0.5">{v}</div>
    </div>
  )
}
