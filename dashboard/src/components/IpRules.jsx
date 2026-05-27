import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import { Button, Card, Empty, ErrorNote, Spinner, fmtDateTime } from './ui'

const PAGE_SIZE = 25

export default function IpRules() {
  const queryClient = useQueryClient()
  const [page, setPage] = useState(0)
  const [form, setForm] = useState({ ip_cidr: '', action: 'BLOCK', reason: '', expires_in_hours: '' })
  const [formError, setFormError] = useState(null)

  const list = useQuery({
    queryKey: ['ip-rules'],
    queryFn: api.listIpRules,
    refetchInterval: 15000,
  })

  const create = useMutation({
    mutationFn: (body) => api.createIpRule(body),
    onSuccess: () => {
      setForm({ ip_cidr: '', action: 'BLOCK', reason: '', expires_in_hours: '' })
      setFormError(null)
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] })
    },
    onError: (e) => setFormError(e.message),
  })

  const remove = useMutation({
    mutationFn: (id) => api.deleteIpRule(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['ip-rules'] }),
    onError: (e) => setFormError(e.message),
  })

  const confirmDelete = (rule) => {
    const msg = `Delete rule for ${rule.ip_cidr} (${rule.action})?`
    if (window.confirm(msg)) remove.mutate(rule.id)
  }

  const rules = list.data || []
  const pages = Math.max(1, Math.ceil(rules.length / PAGE_SIZE))
  const pageRows = useMemo(
    () => rules.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [rules, page]
  )

  const submit = (e) => {
    e.preventDefault()
    if (!form.ip_cidr.trim()) {
      setFormError('IP / CIDR is required')
      return
    }
    create.mutate({
      ip_cidr: form.ip_cidr.trim(),
      action:  form.action,
      reason:  form.reason || null,
      expires_in_hours: form.expires_in_hours ? Number(form.expires_in_hours) : null,
    })
  }

  return (
    <div className="space-y-4">
      <Card title="Add rule">
        <form onSubmit={submit} className="grid grid-cols-1 md:grid-cols-5 gap-2 items-end">
          <Field label="IP / CIDR">
            <input
              className="bg-ink-700 border border-ink-500 rounded px-2 py-1 text-sm w-full font-mono"
              placeholder="10.0.0.1 or 192.168.0.0/24"
              value={form.ip_cidr}
              onChange={(e) => setForm((f) => ({ ...f, ip_cidr: e.target.value }))}
            />
          </Field>
          <Field label="Action">
            <select
              className="bg-ink-700 border border-ink-500 rounded px-2 py-1 text-sm w-full"
              value={form.action}
              onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
            >
              <option value="BLOCK">BLOCK</option>
              <option value="ALLOW">ALLOW</option>
              <option value="CHALLENGE">CHALLENGE</option>
            </select>
          </Field>
          <Field label="Reason">
            <input
              className="bg-ink-700 border border-ink-500 rounded px-2 py-1 text-sm w-full"
              placeholder="optional note"
              value={form.reason}
              onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))}
            />
          </Field>
          <Field label="Expires (hours)">
            <input
              type="number" min="0" step="1"
              className="bg-ink-700 border border-ink-500 rounded px-2 py-1 text-sm w-full"
              placeholder="never"
              value={form.expires_in_hours}
              onChange={(e) => setForm((f) => ({ ...f, expires_in_hours: e.target.value }))}
            />
          </Field>
          <Button type="submit" variant="primary" disabled={create.isPending}>
            {create.isPending ? <Spinner /> : null} Add rule
          </Button>
        </form>
        {formError && <div className="mt-2 text-sm text-rose-300">{formError}</div>}
      </Card>

      <Card title={`Rules (${rules.length})`}>
        <ErrorNote error={list.error} />
        {list.isLoading && <Spinner />}
        {!list.isLoading && rules.length === 0 && <Empty message="No IP rules. Add one above to start." />}
        {pageRows.length > 0 && (
          <table className="w-full text-sm">
            <thead className="text-left text-ink-300 border-b border-ink-600">
              <tr>
                <th className="py-1.5 pr-3 font-medium">CIDR</th>
                <th className="py-1.5 pr-3 font-medium">Action</th>
                <th className="py-1.5 pr-3 font-medium">Reason</th>
                <th className="py-1.5 pr-3 font-medium">Created</th>
                <th className="py-1.5 pr-3 font-medium">Expires</th>
                <th className="py-1.5 pr-3 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {pageRows.map((r) => (
                <tr key={r.id} className="border-b border-ink-700/50">
                  <td className="py-1.5 pr-3 font-mono text-xs">{r.ip_cidr}</td>
                  <td className="py-1.5 pr-3 font-mono text-xs">{r.action}</td>
                  <td className="py-1.5 pr-3 text-xs">{r.reason || '—'}</td>
                  <td className="py-1.5 pr-3 text-xs">{fmtDateTime(r.created_at)}</td>
                  <td className="py-1.5 pr-3 text-xs">{r.expires_at ? fmtDateTime(r.expires_at) : 'never'}</td>
                  <td className="py-1.5 pr-3 text-right">
                    <Button variant="danger" onClick={() => confirmDelete(r)} disabled={remove.isPending}>
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {pages > 1 && (
          <div className="flex justify-end gap-2 mt-3 text-sm">
            <Button variant="ghost" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>Prev</Button>
            <span className="text-ink-300 self-center">{page + 1} / {pages}</span>
            <Button variant="ghost" onClick={() => setPage((p) => Math.min(pages - 1, p + 1))} disabled={page >= pages - 1}>Next</Button>
          </div>
        )}
      </Card>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="text-xs uppercase tracking-wider text-ink-300">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  )
}
