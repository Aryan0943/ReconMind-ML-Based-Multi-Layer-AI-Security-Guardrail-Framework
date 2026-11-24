import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json'
  }
});

// System Health
export const getHealth = async () => {
  const resp = await api.get('/health');
  return resp.data;
};

// Security Scanning (Layers 1 to 5)
export const scanInput = async (text, metadata = {}) => {
  const resp = await api.post('/scan/input', { text, metadata });
  return resp.data;
};

export const scanMemory = async (content, sessionId = 'default_session') => {
  const resp = await api.post('/scan/memory', { content, session_id: sessionId });
  return resp.data;
};

export const scanRetrieval = async (content, chunkSize = 500) => {
  const resp = await api.post('/scan/retrieval', { content, chunk_size: chunkSize });
  return resp.data;
};

export const scanTool = async (toolName, userRole, parameters) => {
  const resp = await api.post('/scan/tool', {
    tool_name: toolName,
    user_role: userRole,
    parameters
  });
  return resp.data;
};

export const scanOutput = async (text, redact = true) => {
  const resp = await api.post('/scan/output', { text, redact });
  return resp.data;
};

export const uploadDocument = async (file) => {
  const formData = new FormData();
  formData.append('file', file);
  const resp = await api.post('/scan/document', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  });
  return resp.data;
};

// Dashboard & Analytics
export const getDashboardStats = async () => {
  const resp = await api.get('/dashboard/stats');
  return resp.data;
};

export const getRecentActivity = async () => {
  const resp = await api.get('/dashboard/activity');
  return resp.data;
};

// Logs
export const getSecurityLogs = async (limit = 50, skip = 0, layer = null, action = null) => {
  const params = { limit, skip };
  if (layer) params.layer = layer;
  if (action) params.action = action;
  const resp = await api.get('/logs', { params });
  return resp.data;
};

// Model Metrics & Status
export const getModelMetrics = async () => {
  const resp = await api.get('/models/metrics');
  return resp.data;
};

export const getModelStatus = async () => {
  const resp = await api.get('/models/status');
  return resp.data;
};

// Policies
export const getPolicies = async () => {
  const resp = await api.get('/policies');
  return resp.data;
};

export const updatePolicy = async (layer, data) => {
  const resp = await api.put('/policies', { layer, ...data });
  return resp.data;
};

export default api;
