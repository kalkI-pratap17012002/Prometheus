// Shared visual primitives — kept in one file because there are few of them
// and they're entirely presentational.

export function Card({ title, action, children, className = '' }) {
  return (
    <div className={`bg-ink-800 border border-ink-600 rounded-lg p-4 ${className}`}>
      {(title || action) && (
        <div className="flex items-center justify-between mb-3">
          {title && <h2 className="text-ink-100 font-semibold tracking-tight">{title}</h2>}
          {action}
        </div>
      )}
      {children}
    </div>
  )
}

export function DecisionBadge({ decision }) {
  const map = {
    ALLOW: 'bg-emerald-900/40 text-emerald-300 border-emerald-700',
    LOG:   'bg-amber-900/40 text-amber-300 border-amber-700',
    BLOCK: 'bg-rose-900/40 text-rose-300 border-rose-700',
  }
  const cls = map[decision] || 'bg-ink-700 text-ink-200 border-ink-500'
  return (
    <span className={`inline-block text-xs font-mono px-2 py-0.5 rounded border ${cls}`}>
      {decision}
    </span>
  )
}

export function KpiCard({ label, value, sub }) {
  return (
    <div className="bg-ink-800 border border-ink-600 rounded-lg p-4">
      <div className="text-xs uppercase tracking-wider text-ink-300">{label}</div>
      <div className="text-2xl font-semibold text-ink-100 mt-1">{value}</div>
      {sub && <div className="text-xs text-ink-300 mt-1">{sub}</div>}
    </div>
  )
}

export function Empty({ message = 'No data yet' }) {
  return (
    <div className="text-center text-ink-300 py-8 text-sm">
      {message}
    </div>
  )
}

export function Spinner() {
  return (
    <div className="inline-block w-4 h-4 border-2 border-ink-300 border-t-transparent rounded-full animate-spin" />
  )
}

export function ErrorNote({ error }) {
  if (!error) return null
  const msg = error.message || String(error)
  return (
    <div className="text-rose-300 text-sm bg-rose-900/20 border border-rose-800 rounded px-3 py-2">
      {msg}
    </div>
  )
}

export function Button({ children, variant = 'default', ...rest }) {
  const base = 'inline-flex items-center gap-1.5 px-3 py-1.5 text-sm rounded border transition-colors disabled:opacity-50 disabled:cursor-not-allowed'
  const variants = {
    default: 'bg-ink-700 hover:bg-ink-600 border-ink-500 text-ink-100',
    primary: 'bg-indigo-600 hover:bg-indigo-500 border-indigo-500 text-white',
    danger:  'bg-rose-700 hover:bg-rose-600 border-rose-600 text-white',
    ghost:   'bg-transparent hover:bg-ink-700 border-transparent text-ink-200',
  }
  return (
    <button className={`${base} ${variants[variant]}`} {...rest}>
      {children}
    </button>
  )
}

export function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleTimeString([], { hour12: false }) + '.' +
    String(d.getMilliseconds()).padStart(3, '0').slice(0, 3)
}

export function fmtDateTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString([], { hour12: false })
}

export function truncate(s, n = 80) {
  if (s == null) return ''
  return s.length > n ? s.slice(0, n) + '…' : s
}
