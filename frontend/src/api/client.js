import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api/v1'

const getApiKey = () =>
  localStorage.getItem('astra_api_key') || import.meta.env.VITE_API_KEY || ''

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
})

client.interceptors.request.use(config => {
  const key = getApiKey()
  if (key) {
    config.headers['X-API-Key'] = key
  }
  return config
})

client.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      error.friendlyMessage = 'API key missing or invalid. Set VITE_API_KEY and restart the dev server.'
    }
    return Promise.reject(error)
  }
)

export const api = {
  getStats: () =>
    client.get('/stats'),
  
  submitScan: (formData) =>
    client.post('/scan/submit', formData),
  
  getScanStatus: (scanId) =>
    client.get(`/scan/${scanId}/status`),
  
  getScanResult: (scanId) =>
    client.get(`/scan/${scanId}`),
  
  getCertPivot: (certHash) =>
    client.get(`/certificate/${certHash}/pivot`),
  
  getIOCFeed: (limit = 50) =>
    client.get(`/feed/iocs?limit=${limit}`),
  
  generateApiKey: () =>
    client.post('/auth/generate'),

  getTakedown: (id) =>
    client.get(`/scan/${id}/takedown`),

  downloadTakedownPdf: async (id) => {
    try {
      return await client.get(`/scan/${id}/takedown/pdf`, {
        responseType: 'blob',
      })
    } catch (error) {
      if (error.response?.data instanceof Blob) {
        try {
          const text = await error.response.data.text()
          const parsed = JSON.parse(text)
          if (parsed?.message) {
            error.friendlyMessage = parsed.message
          }
        } catch {
          // ignore parse errors
        }
      }
      throw error
    }
  },
}

export default client
