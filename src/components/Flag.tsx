import { useId } from 'react'

export function Flag({
  label,
  name,
  tip,
  checked,
  onChange,
}: {
  label: string
  name?: string
  tip: string
  checked: boolean
  onChange: (on: boolean) => void
}) {
  const tipId = useId()
  return (
    <span className="flagwrap">
      <label className={'flag' + (checked ? ' flag-on' : '')}>
        <input
          type="checkbox"
          checked={checked}
          aria-describedby={tipId}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span className="flag-key">{label}</span>
        {name && <span className="flag-name">{name}</span>}
      </label>
      <span role="tooltip" id={tipId} className="tip">
        {tip}
      </span>
    </span>
  )
}
