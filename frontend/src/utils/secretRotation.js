/** Calculate rotation state from the current policy and secret timestamps. */
export function getSecretRotationInfo(secret, intervalDays, warningDays = 14) {
  const reference = secret?.lastRotatedAt || secret?.createdAt
  if (!reference || !Number.isFinite(Number(intervalDays)) || Number(intervalDays) < 1) {
    return { status: 'unknown', dueAt: null, daysRemaining: null }
  }

  const rotatedAt = new Date(reference)
  if (Number.isNaN(rotatedAt.getTime())) {
    return { status: 'unknown', dueAt: null, daysRemaining: null }
  }

  const dueAt = new Date(rotatedAt.getTime() + Number(intervalDays) * 86400000)
  const daysRemaining = Math.ceil((dueAt.getTime() - Date.now()) / 86400000)
  const status = daysRemaining < 0 ? 'overdue'
    : daysRemaining <= warningDays ? 'due-soon' : 'active'

  return { status, dueAt, daysRemaining }
}

export function formatRotationDate(date) {
  return date ? new Date(date).toLocaleDateString() : 'Nepoznato'
}
