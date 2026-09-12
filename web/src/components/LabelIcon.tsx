import { iconPath, nodeColor } from '../graph/icons'
import { categoryOf } from '../graph/schema'

interface Props {
  label: string
  category?: string | null
  severity?: string | null
  size?: number
  className?: string
  color?: string
}

/** Inline SVG icon for a node label in its category (or severity) colour. */
export function LabelIcon({ label, category, severity, size = 14, className, color }: Props) {
  const c = color ?? nodeColor(label, category && category !== 'unknown' ? category : categoryOf(label), severity)
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke={c}
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`shrink-0 ${className ?? ''}`}
      aria-hidden
      dangerouslySetInnerHTML={{ __html: iconPath(label) }}
    />
  )
}
