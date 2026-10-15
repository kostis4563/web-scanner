import { isNative, setUnlockedUser } from '../bridge.js'

export const GH_OWNER = 'kostis4563'
export const GH_REPO = 'web-scanner'
export const REPO_URL = `https://github.com/${GH_OWNER}/${GH_REPO}`
export const PROFILE_URL = `https://github.com/${GH_OWNER}`

export const USERNAME_RE = /^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$/i

const API = 'https://api.github.com'
const STORE_KEY = 'ws.unlock'
const MAX_STAR_PAGES = 10

async function gh(path) {
  let res
  try {
    res = await fetch(API + path)
  } catch {
    throw new Error("Couldn't reach GitHub — check your connection and try again.")
  }
  if ((res.status === 403 || res.status === 429) && res.headers.get('x-ratelimit-remaining') === '0') {
    const reset = Number(res.headers.get('x-ratelimit-reset')) * 1000
    const mins = Math.max(1, Math.ceil((reset - Date.now()) / 60000))
    throw new Error(`GitHub's rate limit was hit — try again in ${mins} min.`)
  }
  return res
}

const unexpected = (res) => new Error(`GitHub answered ${res.status} — try again in a moment.`)

async function hasStarred(login) {
  const want = `${GH_OWNER}/${GH_REPO}`.toLowerCase()
  for (let page = 1; page <= MAX_STAR_PAGES; page++) {
    const res = await gh(`/users/${login}/starred?sort=created&direction=desc&per_page=100&page=${page}`)
    if (!res.ok) throw unexpected(res)
    const list = await res.json()
    if (list.some((r) => r.full_name.toLowerCase() === want)) return true
    if (list.length < 100) return false
  }
  return null
}

export async function verifyGithub(username) {
  const handle = username.trim().replace(/^@/, '')
  const profile = await gh(`/users/${encodeURIComponent(handle)}`)
  if (profile.status === 404) throw new Error(`There's no GitHub user named “${handle}”.`)
  if (!profile.ok) throw unexpected(profile)
  const { login } = await profile.json()
  if (login.toLowerCase() === GH_OWNER.toLowerCase()) return { login, starred: true, follows: true }

  const follow = await gh(`/users/${login}/following/${GH_OWNER}`)
  if (follow.status !== 204 && follow.status !== 404) throw unexpected(follow)

  return { login, starred: await hasStarred(login), follows: follow.status === 204 }
}

export function loadUnlockedUser() {
  if (isNative) return window.__wsUnlockUser || null
  try {
    return localStorage.getItem(STORE_KEY)
  } catch {
    return null
  }
}

export function saveUnlockedUser(login) {
  if (isNative) {
    window.__wsUnlockUser = login
    setUnlockedUser(login)
    return
  }
  try {
    if (login) localStorage.setItem(STORE_KEY, login)
    else localStorage.removeItem(STORE_KEY)
  } catch {
  }
}
