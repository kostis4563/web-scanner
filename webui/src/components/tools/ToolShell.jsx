import { Icon } from '../Icon.jsx'
import { getTool } from '../../data/tools.js'

export default function ToolShell({ toolId, right, children }) {
  const tool = getTool(toolId)
  return (
    <div className="animate-rise pb-14">
      <div className="border-b border-dashed border-line px-4 py-5 sm:px-8">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <Icon name={tool?.icon || 'grid'} className="h-4.5 w-4.5 text-ink-secondary" />
              <h1 className="text-[20px] font-semibold tracking-tight text-ink-strong">{tool?.name}</h1>
            </div>
            {tool?.blurb && (
              <p className="mt-1.5 max-w-[60ch] text-[12.5px] leading-relaxed text-ink-subtle">{tool.blurb}</p>
            )}
          </div>
          {right && <div className="flex shrink-0 items-center gap-2">{right}</div>}
        </div>
      </div>
      <div className="px-4 py-6 sm:px-8">{children}</div>
    </div>
  )
}
