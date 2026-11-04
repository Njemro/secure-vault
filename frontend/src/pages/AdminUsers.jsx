import { useCallback, useEffect, useMemo, useState } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import { listAdminUsers, updateAdminUserRole, updateAdminUserStatus } from '../services/usersApi.js'
import './AdminUsers.css'

const roles = ['DEVELOPER', 'TEAM_LEAD', 'ADMIN']
const statuses = ['ACTIVE', 'SUSPENDED', 'DISABLED']
const formatDate = (value) => value ? new Date(value).toLocaleString() : '—'

export default function AdminUsers() {
  const [users, setUsers] = useState([])
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [selected, setSelected] = useState(null)

  const loadUsers = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true)
    setError('')
  
    try {
      const data = await listAdminUsers()
      setUsers(data)
    } catch (err) {
      setError(err.message || 'Nije moguće učitati korisnike.')
    } finally {
      if (showLoading) setLoading(false)
    }
  }, [])
  
  useEffect(() => {
    let cancelled = false
  
    async function fetchUsers() {
      setError('')
    
      try {
        const data = await listAdminUsers()
        if (!cancelled) setUsers(data)
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Nije moguće učitati korisnike.')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
  
    fetchUsers()
  
    return () => {
      cancelled = true
    }
  }, [])

  const filtered = useMemo(() => users.filter((item) =>
    item.username?.toLowerCase().includes(search.trim().toLowerCase()) &&
    (roleFilter === 'ALL' || item.role === roleFilter) &&
    (statusFilter === 'ALL' || item.status === statusFilter)
  ), [users, search, roleFilter, statusFilter])

  async function changeRole(user, role) {
    if (role === user.role || !window.confirm(
      `Promijeniti ulogu korisnika ${user.username} u ${role}? Korisnik će biti odjavljen sa svih aktivnih sesija.`
    )) return
    setBusyId(user.id); setError(''); setNotice('')
    try {
      await updateAdminUserRole(user.id, role)
      setNotice(`Uloga korisnika ${user.username} promijenjena je u ${role}. Korisnik je odjavljen.`)
      await loadUsers()
    } catch (err) { setError(err.message || 'Promjena uloge nije uspjela.') }
    finally { setBusyId(null) }
  }

  async function changeStatus(user, status) {
    if (status === user.status || !window.confirm(
      `Promijeniti status korisnika ${user.username} u ${status}? Sve aktivne sesije biće odjavljene.`
    )) return
    setBusyId(user.id); setError(''); setNotice('')
    try {
      await updateAdminUserStatus(user.id, status)
      setNotice(`Status korisnika ${user.username} promijenjen je u ${status}.`)
      await loadUsers()
    } catch (err) { setError(err.message || 'Promjena statusa nije uspjela.') }
    finally { setBusyId(null) }
  }

  return <section className="admin-users-page">
    <PageHeader title="Upravljanje korisnicima" subtitle="Pregled naloga, dodjela uloga i upravljanje pristupom Secure Vault aplikaciji." />
    {error && <p className="admin-users-alert admin-users-alert--error" role="alert">{error}</p>}
    {notice && <p className="admin-users-alert admin-users-alert--success" role="status">{notice}</p>}
    <div className="admin-users-toolbar">
      <input aria-label="Pretraga korisnika" placeholder="Pretraži korisničko ime..." value={search} onChange={(e) => setSearch(e.target.value)} />
      <select aria-label="Filter uloge" value={roleFilter} onChange={(e) => setRoleFilter(e.target.value)}>
        <option value="ALL">Sve uloge</option>{roles.map((r) => <option key={r}>{r}</option>)}
      </select>
      <select aria-label="Filter statusa" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
        <option value="ALL">Svi statusi</option>{statuses.map((s) => <option key={s}>{s}</option>)}
      </select>
      <button type="button" onClick={loadUsers} disabled={loading}>Osvježi</button>
    </div>
    <div className="admin-users-table-wrap"><table className="admin-users-table">
      <thead><tr><th>Korisničko ime</th><th>Uloga</th><th>Status</th><th>Kreiran</th><th>Promjena statusa</th></tr></thead>
      <tbody>{loading ? <tr><td colSpan="5">Učitavanje korisnika...</td></tr> :
        filtered.length === 0 ? <tr><td colSpan="5">Nema korisnika za zadate kriterijume.</td></tr> :
        filtered.map((item) => <tr key={item.id}>
          <td><button className="admin-users-detail-link" type="button" onClick={() => setSelected(selected?.id === item.id ? null : item)}>{item.username}</button>
            {selected?.id === item.id && <div className="admin-users-details"><strong>Detalji naloga</strong><span>ID: {item.id}</span><span>Uloga: {item.role}</span><span>Status: {item.status}</span><span>Kreiran: {formatDate(item.createdAt)}</span></div>}
          </td>
          <td><select aria-label={`Uloga za ${item.username}`} value={item.role} disabled={busyId === item.id} onChange={(e) => changeRole(item, e.target.value)}>{roles.map((r) => <option key={r}>{r}</option>)}</select></td>
          <td><span className={`admin-users-status admin-users-status--${item.status.toLowerCase()}`}>{item.status}</span></td>
          <td>{formatDate(item.createdAt)}</td>
          <td><select aria-label={`Status za ${item.username}`} value={item.status} disabled={busyId === item.id} onChange={(e) => changeStatus(item, e.target.value)}>{statuses.map((s) => <option key={s}>{s}</option>)}</select></td>
        </tr>)}
      </tbody>
    </table></div>
  </section>
}
