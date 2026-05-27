import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { api } from '../api'
import { Button, Card, Empty, ErrorNote, KpiCard, Spinner, fmtDateTime } from './ui'

export default function ModelPerf() {
  const queryClient = useQueryClient()
  const bench = useQuery({ queryKey: ['benchmark'], queryFn: api.benchmark, retry: 0 })
  const importances = useQuery({ queryKey: ['feature-importances'], queryFn: api.featureImportances, retry: 0 })
  const history = useQuery({ queryKey: ['retrain-history'], queryFn: api.retrainHistory, refetchInterval: 5000 })
  const [activeJob, setActiveJob] = useState(null)

  const trigger = useMutation({
    mutationFn: api.triggerRetrain,
    onSuccess: (data) => setActiveJob(data.job_id),
    onError: () => setActiveJob(null),
  })

  const jobQ = useQuery({
    queryKey: ['retrain-job', activeJob],
    queryFn: () => api.retrainStatus(activeJob),
    enabled: !!activeJob,
    refetchInterval: (q) => {
      const s = q.state.data?.status
      if (s === 'completed' || s === 'rejected' || s === 'failed') return false
      return 2000
    },
  })

  useEffect(() => {
    const s = jobQ.data?.status
    if (s === 'completed' || s === 'rejected' || s === 'failed') {
      queryClient.invalidateQueries({ queryKey: ['retrain-history'] })
    }
  }, [jobQ.data?.status, queryClient])

  const rows = bench.data?.rows || []
  const latency = bench.data?.latency_ms
  // Find the XGBoost row so we can render a confusion-matrix heatmap; that's
  // the model we actually run in prod.
  const xgb = rows.find((r) => /xgb/i.test(r.model))

  const topImportances = Object.entries(importances.data || {})
    .map(([name, value]) => ({ name, value: Number(value) }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 10)

  const retrainResult = jobQ.data?.result
  const retrainVerdict = (() => {
    if (!jobQ.data) return null
    const s = jobQ.data.status
    if (s === 'completed') return { tone: 'good', label: 'IMPROVED' }
    if (s === 'rejected')  return { tone: 'warn', label: 'REJECTED' }
    if (s === 'failed')    return { tone: 'bad',  label: 'FAILED' }
    return null
  })()

  return (
    <div className="space-y-4">
      <ErrorNote error={bench.error} />

      {latency && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <KpiCard label="Inference p50" value={`${latency.p50.toFixed(2)} ms`} sub={`mean ${latency.mean.toFixed(2)} ms`} />
          <KpiCard label="Inference p95" value={`${latency.p95.toFixed(2)} ms`} sub={`n = ${latency.n}`} />
          <KpiCard label="Inference p99" value={`${latency.p99.toFixed(2)} ms`} sub={`budget ${latency.budget_ms} ms · ${latency.p99_under_budget ? 'ok' : 'OVER'}`} />
        </div>
      )}

      <Card
        title="Precision / Recall / F1 (test set)"
        action={
          <Button
            variant="primary"
            onClick={() => trigger.mutate()}
            disabled={trigger.isPending || (jobQ.data && ['pending', 'running'].includes(jobQ.data.status))}
          >
            {trigger.isPending ? <Spinner /> : null} Trigger Retraining
          </Button>
        }
      >
        {bench.isLoading && <Spinner />}
        {!bench.isLoading && rows.length === 0 && <Empty message="No benchmark_report.json yet. Run train.py + evaluate.py to populate." />}
        {rows.length > 0 && (
          <table className="w-full text-sm">
            <thead className="text-left text-ink-300 border-b border-ink-600">
              <tr>
                <th className="py-1.5 pr-3 font-medium">Model</th>
                <th className="py-1.5 pr-3 font-medium text-right">Precision</th>
                <th className="py-1.5 pr-3 font-medium text-right">Recall</th>
                <th className="py-1.5 pr-3 font-medium text-right">F1</th>
                <th className="py-1.5 pr-3 font-medium text-right">AUC</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.model} className="border-b border-ink-700/50">
                  <td className="py-1.5 pr-3">{r.model}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-right">{r.precision?.toFixed(3)}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-right">{r.recall?.toFixed(3)}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-right">{r.f1?.toFixed(3)}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs text-right">{r.auc?.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Top feature importances (XGBoost)">
          <ErrorNote error={importances.error} />
          {importances.isLoading && <Spinner />}
          {!importances.isLoading && topImportances.length === 0 && (
            <Empty message="No feature_importances.json yet. Run train.py to populate." />
          )}
          {topImportances.length > 0 && (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topImportances} layout="vertical" margin={{ left: 100, right: 24 }}>
                  <XAxis type="number" stroke="#7a8197" fontSize={11} />
                  <YAxis dataKey="name" type="category" stroke="#7a8197" fontSize={11} width={150} />
                  <Tooltip
                    contentStyle={{ background: '#11141c', border: '1px solid #252a39', fontSize: 12 }}
                    formatter={(v) => v.toFixed(4)}
                  />
                  <Bar dataKey="value" fill="#6366f1" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card title="Confusion matrix (XGBoost)">
          {xgb?.confusion ? <ConfusionMatrix matrix={xgb.confusion} /> : <Empty />}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4">
        <Card title="Retrain status">
          {!activeJob && !history.data?.length && <Empty message="No retraining yet. Click Trigger Retraining above." />}
          {activeJob && jobQ.data && (
            <div className="space-y-2 text-sm">
              <Row k="Job" v={<span className="font-mono">{activeJob.slice(0, 8)}</span>} />
              <Row k="Status" v={<StatusPill s={jobQ.data.status} />} />
              <Row k="Feedback samples" v={jobQ.data.n_feedback} />
              {retrainResult?.old_metrics && (
                <Row k="Old F1" v={retrainResult.old_metrics.f1.toFixed(4)} />
              )}
              {retrainResult?.new_metrics && (
                <Row k="New F1" v={retrainResult.new_metrics.f1.toFixed(4)} />
              )}
              {retrainVerdict && retrainResult?.old_metrics && retrainResult?.new_metrics && (
                <div className={`mt-1 text-sm rounded px-3 py-2 border ${
                  retrainVerdict.tone === 'good' ? 'bg-emerald-900/30 text-emerald-200 border-emerald-700' :
                  retrainVerdict.tone === 'warn' ? 'bg-amber-900/30 text-amber-200 border-amber-700' :
                                                   'bg-rose-900/30 text-rose-200 border-rose-700'
                }`}>
                  {retrainVerdict.label}: ΔF1 = {(retrainResult.new_metrics.f1 - retrainResult.old_metrics.f1).toFixed(4)}
                </div>
              )}
              {jobQ.data.error && <div className="text-rose-300 text-sm">{jobQ.data.error}</div>}
            </div>
          )}

          {history.data && history.data.length > 0 && (
            <>
              <div className="mt-4 text-xs uppercase tracking-wider text-ink-300">History</div>
              <table className="w-full text-xs mt-1">
                <tbody>
                  {history.data.slice(-10).reverse().map((h, i) => (
                    <tr key={i} className="border-b border-ink-700/30">
                      <td className="py-1 pr-2 font-mono">{h.job_id?.slice(0, 8) || '—'}</td>
                      <td className="py-1 pr-2"><StatusPill s={h.status} /></td>
                      <td className="py-1 pr-2 text-ink-300">{h.ts ? fmtDateTime(new Date(h.ts * 1000).toISOString()) : '—'}</td>
                      <td className="py-1 pr-2 font-mono text-right">
                        {h.new_metrics?.f1?.toFixed(3) || ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </Card>
      </div>
    </div>
  )
}

function Row({ k, v }) {
  return (
    <div className="flex justify-between">
      <span className="text-ink-300">{k}</span>
      <span className="text-ink-100">{v}</span>
    </div>
  )
}

function StatusPill({ s }) {
  const map = {
    completed: 'bg-emerald-900/40 text-emerald-300 border-emerald-700',
    running:   'bg-indigo-900/40 text-indigo-300 border-indigo-700',
    pending:   'bg-ink-700 text-ink-200 border-ink-500',
    rejected:  'bg-amber-900/40 text-amber-300 border-amber-700',
    failed:    'bg-rose-900/40 text-rose-300 border-rose-700',
  }
  return <span className={`inline-block text-xs font-mono px-2 py-0.5 rounded border ${map[s] || 'bg-ink-700 border-ink-500'}`}>{s}</span>
}

function ConfusionMatrix({ matrix }) {
  // matrix: [[tn, fp], [fn, tp]]
  const flat = matrix.flat()
  const max = Math.max(...flat, 1)
  const cell = (v, lbl, kind) => {
    const intensity = v / max
    const bg = kind === 'good'
      ? `rgba(16, 185, 129, ${0.15 + intensity * 0.55})`
      : `rgba(244, 63, 94, ${0.15 + intensity * 0.55})`
    return (
      <div className="flex flex-col items-center justify-center rounded p-3 border border-ink-600" style={{ background: bg }}>
        <div className="text-xs uppercase tracking-wider text-ink-200">{lbl}</div>
        <div className="text-xl font-semibold text-ink-100 font-mono">{v}</div>
      </div>
    )
  }
  return (
    <div className="grid grid-cols-[auto_1fr_1fr] gap-2 text-xs">
      <div></div>
      <div className="text-center text-ink-300">Pred: Normal</div>
      <div className="text-center text-ink-300">Pred: Attack</div>
      <div className="self-center text-ink-300">Actual: Normal</div>
      {cell(matrix[0][0], 'TN', 'good')}
      {cell(matrix[0][1], 'FP', 'bad')}
      <div className="self-center text-ink-300">Actual: Attack</div>
      {cell(matrix[1][0], 'FN', 'bad')}
      {cell(matrix[1][1], 'TP', 'good')}
    </div>
  )
}
