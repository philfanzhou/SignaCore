import axios from 'axios'

// Axios's fetch adapter maps false to Request.credentials = 'omit', including same-origin cookies.
// Manual redirects keep a management credential from being forwarded to a different route.
export const credentialFreeClient = axios.create({
  adapter: 'fetch',
  withCredentials: false,
  fetchOptions: { redirect: 'manual' },
})
