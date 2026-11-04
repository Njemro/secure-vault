
import { authenticatedFetch, readJson } from './api.js'

export async function getSecurityPolicy() {
  const response = await authenticatedFetch('/security-policies', {
    method: 'GET',
  })

  return readJson(response)
}

export async function updateSecurityPolicy(policy) {
  const response = await authenticatedFetch('/security-policies', {
    method: 'PUT',
    body: policy,
  })

  return readJson(response)
}
