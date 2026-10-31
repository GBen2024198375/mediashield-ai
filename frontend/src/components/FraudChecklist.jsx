function urgencyClass(u) {
  if (u === 'immediate') return 'urgency-immediate'
  if (u === 'warn') return 'urgency-warn'
  return 'urgency-info'
}

export default function FraudChecklist({ data }) {
  if (!data || !data.items || data.items.length === 0) {
    return null
  }

  const { title, urgency, items, sources, disclaimer } = data

  return (
    <div className="card">
      <div className="checklist-header">
        <div>
          <div className="checklist-title">{title}</div>
          {sources && sources.length > 0 && (
            <div className="checklist-sources">
              Personalized for: {sources.join(' · ')}
            </div>
          )}
        </div>
        <span className={`badge ${urgencyBadge(urgency)}`}>
          {urgency === 'immediate' ? 'Act now' :
           urgency === 'warn' ? 'Review' : 'Advisory'}
        </span>
      </div>

      <ul className="checklist-items">
        {items.map((item, i) => (
          <li
            key={i}
            className={`checklist-item ${urgencyClass(urgencyFor(item.priority))}`}
          >
            <div className="checklist-icon">{item.icon}</div>
            <div className="checklist-body">
              <div className="checklist-item-title">{item.title}</div>
              <div className="checklist-item-detail">{item.detail}</div>
              {item.tags && item.tags.length > 0 && (
                <div className="checklist-tags">
                  {item.tags.map((t) => (
                    <span key={t} className="checklist-tag">{t}</span>
                  ))}
                </div>
              )}
            </div>
          </li>
        ))}
      </ul>

      {disclaimer && <div className="checklist-disclaimer">{disclaimer}</div>}
    </div>
  )
}

function urgencyFor(priority) {
  if (priority <= 10) return 'immediate'
  if (priority <= 40) return 'warn'
  return 'info'
}

function urgencyBadge(u) {
  if (u === 'immediate') return 'high'
  if (u === 'warn') return 'mid'
  return 'low'
}