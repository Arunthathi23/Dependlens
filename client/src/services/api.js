import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5000/api",
});

export const getStats = () => api.get("/stats");
export const getGraph = () => api.get("/graph");
export const getPriorities = () => api.get("/priorities");
export const getValidation = () => api.get("/validation");
export const getVulnerabilityInstances = () => api.get("/vulnerability-instances");
export const getPackage = (id) => api.get(`/package/${id}`);

export default api;
