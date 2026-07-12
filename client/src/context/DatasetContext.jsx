import React, { createContext, useContext, useState, useEffect } from 'react';
import { getStats, getGraph, getPriorities, getValidation, getAISummary, resetToSample, getPackage } from '../services/api';

const DatasetContext = createContext();

export function useDataset() {
  return useContext(DatasetContext);
}

export function DatasetProvider({ children }) {
  const [activeDataset, setActiveDataset] = useState(() => {
    return localStorage.getItem('activeDataset') || 'sample';
  });

  const [analysisResult, setAnalysisResult] = useState(() => {
    const cached = localStorage.getItem('analysisResult');
    return cached ? JSON.parse(cached) : null;
  });

  // Sync to localStorage
  useEffect(() => {
    localStorage.setItem('activeDataset', activeDataset);
    if (analysisResult) {
      localStorage.setItem('analysisResult', JSON.stringify(analysisResult));
    } else {
      localStorage.removeItem('analysisResult');
    }
  }, [activeDataset, analysisResult]);

  // Method to set uploaded dataset state
  const setUploadedDataset = (result) => {
    setAnalysisResult(result);
    setActiveDataset('uploaded');
  };

  // Reset back to sample
  const resetDataset = async () => {
    await resetToSample();
    setAnalysisResult(null);
    setActiveDataset('sample');
  };

  // Abstracted helper methods that return the correct data source immediately
  const getStatsData = async () => {
    if (activeDataset === 'uploaded' && analysisResult) {
      return { data: analysisResult.stats };
    }
    return getStats();
  };

  const getGraphData = async () => {
    if (activeDataset === 'uploaded' && analysisResult) {
      return { data: analysisResult.graph };
    }
    return getGraph();
  };

  const getPrioritiesData = async () => {
    if (activeDataset === 'uploaded' && analysisResult) {
      return { data: analysisResult.priorities };
    }
    return getPriorities();
  };

  const getValidationData = async () => {
    if (activeDataset === 'uploaded' && analysisResult) {
      return { data: analysisResult.validation };
    }
    return getValidation();
  };

  const getAISummaryData = async () => {
    if (activeDataset === 'uploaded' && analysisResult) {
      return { data: analysisResult.aiSummary };
    }
    return getAISummary();
  };

  const getVulnerabilityInstancesData = async () => {
    if (activeDataset === 'uploaded' && analysisResult) {
      return {
        data: {
          totalInstances: analysisResult.summary.totalInstances,
          directVulnerabilities: analysisResult.summary.directVulnerabilities,
          transitiveVulnerabilities: analysisResult.summary.transitiveVulnerabilities,
          instances: analysisResult.vulnerabilityInstances
        }
      };
    }
    return getVulnerabilityInstances();
  };

  // Helper for single package details
  const getPackageData = async (id) => {
    if (activeDataset === 'uploaded' && analysisResult) {
      const node = analysisResult.graph.find(n => n.id === id);
      if (node) return { data: node };
      throw new Error("Package not found in uploaded graph");
    }
    return getPackage(id);
  };

  return (
    <DatasetContext.Provider value={{
      activeDataset,
      analysisResult,
      setUploadedDataset,
      resetDataset,
      getStatsData,
      getGraphData,
      getPrioritiesData,
      getValidationData,
      getAISummaryData,
      getVulnerabilityInstancesData,
      getPackageData
    }}>
      {children}
    </DatasetContext.Provider>
  );
}
