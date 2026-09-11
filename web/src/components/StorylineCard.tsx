import { Crown, Layers, Bell, Clock } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import type { StorylineOut } from '../api/types'
import { bandForScore } from '../api/types'
import { cn, fmtShortTime, shortId } from '../lib/format'
import { LabelIcon } from './LabelIcon'
import { StageStrip } from './StageStrip'
import { ScoreChip } from './chips'

interface Props { story: StorylineOut; compact?: boolean; className?: string; active?: boolean }

/** Storyline summary card: score, actor/campaign, stages, member alerts, crown jewels, time span. */
export function StorylineCard({ story, compact, className, active }: Props) {
  const navigate = useNavigate()
  return (
    <button
      type="button"
      onClick={() => navigate(`/storylines/${encodeURIComponent(story.id)}`)}
      className={cn('panel block w-full text-left transition-colors hover:border-line-2 hover:bg-panel-2', active && 'border-accent/60', className)}
    >
      <div className="flex items-start gap-3 p-3">
        <ScoreChip score={story.contextual_score} band={bandForScore(story.contextual_score)} size="lg" />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <LabelIcon label="Storyline" size={13} />
            <span className="truncate text-sm font-semibold text-fg" title={story.title}>{story.title}</span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-fg-2">
            {story.actor_name && (
              <span className="chip border-cat-ti/40 bg-cat-ti/10 text-cat-ti">
                <LabelIcon label="ThreatActor" size={10} color="currentColor" /> {story.actor_name}
              </span>
            )}
            {story.campaign_name && <span className="chip border-line-2 text-fg-2">{story.campaign_name}</span>}
            <span className="flex items-center gap-1" title="Kill-chain stages"><Layers size={11} /> {story.stage_count} stages</span>
            <span className="flex items-center gap-1" title="Member alerts"><Bell size={11} /> {story.alert_ids.length} alerts</span>
            <span className={cn('flex items-center gap-1', story.crown_jewels_reached.length && 'text-sev-critical')} title={story.crown_jewels_reached.map(shortId).join('\n')}>
              <Crown size={11} /> {story.crown_jewels_reached.length} crown jewel{story.crown_jewels_reached.length === 1 ? '' : 's'}
            </span>
            <span className="flex items-center gap-1 mono" title="First to last event (UTC)"><Clock size={11} /> {fmtShortTime(story.first_event)} → {fmtShortTime(story.last_event)}</span>
          </div>
          {!compact && <p className="mt-1.5 line-clamp-2 text-xs leading-snug text-fg-2">{story.summary}</p>}
          {!compact && story.stages.length > 0 && <StageStrip stages={story.stages} compact className="mt-2" />}
        </div>
      </div>
    </button>
  )
}
