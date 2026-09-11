import { ArrowLeft, Bot, ExternalLink } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useNodesBatch } from '../../api/hooks'
import type { StorylineOut } from '../../api/types'
import { bandForScore } from '../../api/types'
import { LabelIcon } from '../../components/LabelIcon'
import { NodeRef } from '../../components/NodeRef'
import { ScoreChip } from '../../components/chips'
import { fmtTime } from '../../lib/format'
import { useCanvasStore } from '../../store/canvasStore'
import { useDrawerStore } from '../../store/drawerStore'

export function StorylineHeader({ story }: { story: StorylineOut }) {
  const navigate = useNavigate()
  const askAbout = useDrawerStore((s) => s.askAbout)
  const setSeed = useCanvasStore((s) => s.setExplorerSeed)
  const jewels = useNodesBatch(story.crown_jewels_reached)
  const jewelNode = (id: string) => jewels.data?.nodes.find((n) => n.id === id)
  const openExplorer = () => {
    if (story.fragment) setSeed(story.fragment)
    navigate(story.fragment ? '/explorer' : `/explorer?id=${encodeURIComponent(story.id)}`)
  }
  return (
    <div className="border-b border-line px-4 pb-3 pt-3">
      <button type="button" className="btn-ghost -ml-2 mb-1 py-0" onClick={() => navigate('/storylines')}>
        <ArrowLeft size={12} /> Storylines
      </button>
      <div className="flex flex-wrap items-start gap-3">
        <ScoreChip score={story.contextual_score} band={bandForScore(story.contextual_score)} size="lg" className="mt-0.5 h-10 min-w-[52px] text-xl" />
        <div className="min-w-0 flex-1">
          <h1 className="flex items-center gap-2 text-base font-semibold leading-snug text-fg">
            <LabelIcon label="Storyline" size={16} /> {story.title}
          </h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-2">
            {story.actor_id && (
              <button type="button" className="chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti hover:bg-cat-ti/20" onClick={() => navigate(`/threat-intel/actors/${encodeURIComponent(story.actor_id!)}`)}>
                <LabelIcon label="ThreatActor" size={11} color="currentColor" /> {story.actor_name ?? story.actor_id}
              </button>
            )}
            {story.campaign_id && (
              <button type="button" className="chip border-line-2 text-fg-2 hover:bg-panel-3" onClick={() => navigate(`/threat-intel/campaigns/${encodeURIComponent(story.campaign_id!)}`)}>
                <LabelIcon label="Campaign" size={11} /> {story.campaign_name ?? story.campaign_id}
              </button>
            )}
            <span>{story.stage_count} stages</span>
            <span className="text-fg-3">·</span>
            <span>{story.alert_ids.length} alerts</span>
            <span className="text-fg-3">·</span>
            <span className="mono">
              {fmtTime(story.first_event)} → {fmtTime(story.last_event)}
            </span>
            <span className="text-fg-3">·</span>
            <span className="mono text-[10.5px] text-fg-3">{story.id}</span>
          </div>
          <p className="mt-1.5 max-w-4xl text-xs leading-snug text-fg-2">{story.summary}</p>
          {story.crown_jewels_reached.length > 0 && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1 text-xs">
              <span className="text-sev-critical">Crown jewels reached:</span>
              {story.crown_jewels_reached.map((j) => (
                <NodeRef key={j} id={j} node={jewelNode(j)} />
              ))}
            </div>
          )}
        </div>
        <div className="flex shrink-0 flex-col gap-1.5">
          <button type="button" className="btn-primary" onClick={() => askAbout(`Summarise the storyline "${story.title}" stage by stage with technique IDs, then tell me what to contain first.`, { storyline_id: story.id })}>
            <Bot size={13} /> Ask analyst about this storyline
          </button>
          <button type="button" className="btn" onClick={openExplorer}>
            <ExternalLink size={13} /> Open in explorer
          </button>
        </div>
      </div>
    </div>
  )
}
