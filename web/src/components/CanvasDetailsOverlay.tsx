import { NodeDetailsPanel } from './NodeDetailsPanel'

interface Props {
  nodeId: string | null
  onClose: () => void
  onExpand?: (id: string) => void
  onBlastRadius?: (id: string) => void
  inExplorer?: boolean
}

/** Node details floating over the right edge of a canvas (rendered as a GraphCanvas child). */
export function CanvasDetailsOverlay({ nodeId, onClose, onExpand, onBlastRadius, inExplorer }: Props) {
  if (!nodeId) return null
  return (
    <div className="absolute bottom-2 right-2 top-12 z-30 w-[340px] max-w-[60%] overflow-hidden rounded-lg border border-line bg-panel/95 shadow-2xl backdrop-blur">
      <NodeDetailsPanel key={nodeId} nodeId={nodeId} onClose={onClose} onExpand={onExpand} onBlastRadius={onBlastRadius} inExplorer={inExplorer} />
    </div>
  )
}
