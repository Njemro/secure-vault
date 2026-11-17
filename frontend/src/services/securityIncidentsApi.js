import { request } from './api.js'

export function getSecurityIncidents() {
  return request('/admin/security-incidents', { method: 'GET' })
}

export function getHoneypotDemoStatus() {
  return request('/honeypot/demo/status', { method: 'GET' })
}

export function enableHoneypotDemo(durationMinutes) {
  return request('/honeypot/demo/enable', {
    method: 'POST',
    body: { durationMinutes: Number(durationMinutes) },
  })
}

export function disableHoneypotDemo() {
  return request('/honeypot/demo/disable', { method: 'POST' })
}
