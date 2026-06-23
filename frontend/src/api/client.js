import axios from 'axios'

const BASE_URL = 'http://localhost:5000/api/v1'

const getApiKey = () =>
  localStorage.getItem('astra_api_key') || 'dev-master-key'

const client = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
})

client.interceptors.request.use(config => {
  config.headers['X-API-Key'] = getApiKey()
  return config
})

export const api = {
  getStats: () =>
    client.get('/stats'),
  
  submitScan: (formData) =>
    client.post('/scan/submit', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    }),
  
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
}

export default client
