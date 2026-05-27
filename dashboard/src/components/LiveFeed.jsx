import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { Card, DecisionBadge, Empty, ErrorNote, Spinner, fmtTime, truncate } from './ui'
import RequestDetail from './RequestDetail'

const POLL_MS = 3000

export default function LiveFeed() {
  const [selectedId, setSelectedId] = useState(null)
  const [filter, setFilter] = useState({ decision: '', ip: '' })

  const { data, isLoading, error, isFetching } = useQuery({
    queryKey: ['requests', filter],
    queryFn: () => api.listRequests({ limit: 50, offset: 0, ...filter }),
    refetchInterval: POLL_MS,
  })

  const rows = data?.items || []

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          Live Feed
          {isFetching && <Spinner />}
          {data && <span className="text-xs text-ink-300 font-normal">({data.total} total)</span>}
        </span>
      }
      action={
        <div className="flex gap-2">
          <select
            className="bg-ink-700 border border-ink-500 text-ink-100 rounded px-2 py-1 text-sm"
            value={filter.decision}
            onChange={(e) => setFilter((f) => ({ ...f, decision: e.target.value }))}
          >
            <option value="">all decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="LOG">LOG</option>
            <option value="BLOCK">BLOCK</option>
          </select>
          <input
            className="bg-ink-700 border border-ink-500 text-ink-100 rounded px-2 py-1 text-sm w-40"
            placeholder="filter ip…"
            value={filter.ip}
            onChange={(e) => setFilter((f) => ({ ...f, ip: e.target.value }))}
          />
        </div>
      }
    >
      <ErrorNote error={error} />
      <div className="overflow-x-auto -mx-4 px-4">
        <table className="w-full text-sm">
          <thead className="text-left text-ink-300 border-b border-ink-600">
            <tr>
              <th className="py-2 pr-3 font-medium">Time</th>
              <th className="py-2 pr-3 font-medium">IP</th>
              <th className="py-2 pr-3 font-medium">Method</th>
              <th className="py-2 pr-3 font-medium">URI</th>
              <th className="py-2 pr-3 font-medium text-right">ML</th>
              <th className="py-2 pr-3 font-medium text-right">ModSec</th>
              <th className="py-2 pr-3 font-medium">Decision</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.id}
                onClick={() => setSelectedId(r.id)}
                className="border-b border-ink-700/50 hover:bg-ink-700/50 cursor-pointer"
              >
                <td className="py-1.5 pr-3 font-mono text-xs text-ink-200">{fmtTime(r.timestamp)}</td>
                <td className="py-1.5 pr-3 font-mono text-xs">{r.client_ip}</td>
                <td className="py-1.5 pr-3 font-mono text-xs">{r.method}</td>
                <td className="py-1.5 pr-3 font-mono text-xs text-ink-200" title={r.uri}>
                  {truncate(r.uri, 60)}
                </td>
                <td className="py-1.5 pr-3 font-mono text-xs text-right">
                  {r.ml_score != null ? r.ml_score.toFixed(2) : '—'}
                </td>
                <td className="py-1.5 pr-3 font-mono text-xs text-right">
                  {r.modsec_score != null ? r.modsec_score.toFixed(2) : '—'}
                </td>
                <td className="py-1.5 pr-3"><DecisionBadge decision={r.decision} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        {isLoading && <div className="py-4 text-center"><Spinner /></div>}
        {!isLoading && rows.length === 0 && <Empty message="No requests yet — send some traffic through Nginx to populate this feed." />}
      </div>

      {selectedId != null && (
        <RequestDetail
          requestId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </Card>
  )
}
