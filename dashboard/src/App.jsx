import { useState } from 'react'
import LiveFeed from './components/LiveFeed'
import Stats from './components/Stats'
import IpRules from './components/IpRules'
import ModelPerf from './components/ModelPerf'

const ChartIcon = (props) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...props}>
    <path d="M3 3v18h18" /><path d="M7 15l4-4 3 3 5-6" />
  </svg>
)
const FeedIcon = (props) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...props}>
    <path d="M4 11a9 9 0 0 1 9 9" /><path d="M4 4a16 16 0 0 1 16 16" /><circle cx="5" cy="19" r="1.5" />
  </svg>
)
const ShieldIcon = (props) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...props}>
    <path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z" />
  </svg>
)
const CpuIcon = (props) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" {...props}>
    <rect x="6" y="6" width="12" height="12" rx="1" /><rect x="9" y="9" width="6" height="6" />
    <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" />
  </svg>
)

const PAGES = [
  { id: 'stats', label: 'Overview',  Icon: ChartIcon,  Component: Stats },
  { id: 'feed',  label: 'Live Feed', Icon: FeedIcon,   Component: LiveFeed },
  { id: 'ip',    label: 'IP Rules',  Icon: ShieldIcon, Component: IpRules },
  { id: 'model', label: 'Model',     Icon: CpuIcon,    Component: ModelPerf },
]

export default function App() {
  const [page, setPage] = useState('stats')
  const Active = PAGES.find((p) => p.id === page).Component

  return (
    <div className="min-h-full flex">
      <aside className="w-56 shrink-0 border-r border-ink-700 bg-ink-800/60 backdrop-blur sticky top-0 h-screen flex flex-col">
        <div className="flex items-center gap-2 px-4 py-4 border-b border-ink-700">
          <div className="w-7 h-7 rounded bg-indigo-600 flex items-center justify-center text-white font-bold text-sm">W</div>
          <h1 className="text-ink-100 font-semibold tracking-tight text-sm">ML-WAF Console</h1>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-1">
          {PAGES.map((p) => {
            const active = page === p.id
            return (
              <button
                key={p.id}
                onClick={() => setPage(p.id)}
                className={
                  'w-full flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors ' +
                  (active
                    ? 'bg-ink-700 text-ink-100 border border-ink-500'
                    : 'text-ink-300 hover:text-ink-100 hover:bg-ink-700/50 border border-transparent')
                }
              >
                <p.Icon className="w-4 h-4" />
                <span>{p.label}</span>
              </button>
            )
          })}
        </nav>
        <div className="px-4 py-3 text-[10px] text-ink-300 border-t border-ink-700">
          phase 5 · SHAP-explainable WAF
        </div>
      </aside>

      <main className="flex-1 min-w-0 px-6 py-5">
        <Active />
      </main>
    </div>
  )
}
