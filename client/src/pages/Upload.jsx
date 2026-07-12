import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { analyzeSBOM } from '../services/api';
import { useDataset } from '../context/DatasetContext';
import './Upload.css';

export default function Upload() {
  const navigate = useNavigate();
  const { setUploadedDataset, resetDataset } = useDataset();

  // State to hold selected files
  const [files, setFiles] = useState({
    applications: null,
    dependencies: null,
    vulnerabilities: null,
    licenses: null,
    transitiveDependencies: null,
    labels: null
  });

  const [loading, setLoading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successStats, setSuccessStats] = useState(null);

  const steps = [
    "Uploading raw files...",
    "Building dependency graph mapping...",
    "Resolving transitive CVE vulnerabilities...",
    "Running copyleft license risk engine...",
    "Computing compounded vulnerability risk...",
    "Synthesizing explainable AI intelligence..."
  ];

  // Validate file extensions
  const validateFile = (file, expectedType) => {
    if (!file) return null;
    const name = file.name.toLowerCase();
    if (expectedType === 'json' && !name.endsWith('.json')) {
      return "Only JSON (.json) files are permitted.";
    }
    if (expectedType === 'csv' && !name.endsWith('.csv')) {
      return "Only CSV (.csv) files are permitted.";
    }
    return null;
  };

  const handleFileChange = (key, file, type) => {
    setErrorMsg(null);
    if (!file) {
      setFiles(prev => ({ ...prev, [key]: null }));
      return;
    }
    const error = validateFile(file, type);
    if (error) {
      setErrorMsg(`${file.name}: ${error}`);
      return;
    }
    setFiles(prev => ({ ...prev, [key]: file }));
  };

  const handleReset = async () => {
    try {
      setLoading(true);
      setErrorMsg(null);
      setSuccessStats(null);
      await resetDataset();
      alert("Successfully restored sample dataset.");
      navigate("/");
    } catch (err) {
      setErrorMsg("Failed to reset dataset: " + (err.response?.data?.error || err.message));
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = async () => {
    // Validate required files
    if (!files.applications || !files.dependencies || !files.vulnerabilities || !files.licenses) {
      setErrorMsg("Please upload all 4 required files: applications, dependencies, vulnerabilities, and licenses.");
      return;
    }

    try {
      setLoading(true);
      setErrorMsg(null);
      setSuccessStats(null);

      // Simple artificial interval loops to display status animation
      let stepIndex = 0;
      setCurrentStep(0);
      const stepTimer = setInterval(() => {
        if (stepIndex < steps.length - 1) {
          stepIndex++;
          setCurrentStep(stepIndex);
        }
      }, 700);

      const formData = new FormData();
      formData.append('applications', files.applications);
      formData.append('dependencies', files.dependencies);
      formData.append('vulnerabilities', files.vulnerabilities);
      formData.append('licenses', files.licenses);
      if (files.transitiveDependencies) {
        formData.append('transitiveDependencies', files.transitiveDependencies);
      }
      if (files.labels) {
        formData.append('labels', files.labels);
      }

      const res = await analyzeSBOM(formData);
      clearInterval(stepTimer);

      if (res.data && res.data.status === 'success') {
        setUploadedDataset(res.data);
        setSuccessStats({
          packages: res.data.stats.totalPackages,
          vulnerabilities: res.data.stats.vulnerablePackages,
          critical: res.data.stats.criticalPackages,
          applications: res.data.stats.applications
        });
      }
    } catch (err) {
      setErrorMsg(err.response?.data?.error || err.message || "An unexpected error occurred during SBOM analysis.");
    } finally {
      setLoading(false);
    }
  };

  const getFileLabel = (key) => {
    const map = {
      applications: "applications.json",
      dependencies: "sbom_dependencies.csv",
      vulnerabilities: "vulnerability_db.json",
      licenses: "license_rules.json",
      transitiveDependencies: "transitive_dependencies.json",
      labels: "dependency_labels.csv"
    };
    return map[key];
  };

  const renderUploadCard = (key, type, required = true) => {
    const selectedFile = files[key];

    return (
      <div className={`upload-card ${selectedFile ? 'upload-card--selected' : ''}`} key={key}>
        <div className="upload-card__header">
          <span className="upload-card__title">
            {getFileLabel(key)} {required && <strong className="required-star">*</strong>}
          </span>
          <span className="upload-card__badge">{type.toUpperCase()}</span>
        </div>

        {selectedFile ? (
          <div className="upload-card__selected-info">
            <div className="file-detail">
              <span className="file-icon">📄</span>
              <div className="file-metadata">
                <strong>{selectedFile.name}</strong>
                <span>{(selectedFile.size / 1024).toFixed(1)} KB</span>
              </div>
            </div>
            <button className="btn-clear" onClick={() => handleFileChange(key, null, type)}>
              Remove
            </button>
          </div>
        ) : (
          <div
            className="upload-card__dropzone"
            onDragOver={e => e.preventDefault()}
            onDrop={e => {
              e.preventDefault();
              if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                handleFileChange(key, e.dataTransfer.files[0], type);
              }
            }}
          >
            <label className="dropzone-label">
              <input
                type="file"
                accept={type === 'json' ? '.json' : '.csv'}
                onChange={e => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileChange(key, e.target.files[0], type);
                  }
                }}
                style={{ display: 'none' }}
              />
              <span>Drag & drop file or <strong style={{ color: '#7c3aed', cursor: 'pointer' }}>browse</strong></span>
            </label>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="upload-page">
      <header className="upload-header">
        <h1>Upload SBOM Ingestion Hub</h1>
        <p>Upload your software bill of materials and instantly calculate threat posture and dependency risk chains.</p>
      </header>

      {errorMsg && (
        <div className="alert alert--error">
          <strong>⚠️ Ingestion Validation Error</strong>
          <p>{errorMsg}</p>
        </div>
      )}

      {successStats && (
        <div className="alert alert--success">
          <strong>🟢 Ingestion Success</strong>
          <p>Successfully processed SBOM. All insights dynamically loaded.</p>
          <div className="success-stats-grid">
            <div className="success-stat-item">
              <span className="label">Monitored Packages</span>
              <strong>{successStats.packages}</strong>
            </div>
            <div className="success-stat-item">
              <span className="label">Vulnerable Instances</span>
              <strong>{successStats.vulnerabilities}</strong>
            </div>
            <div className="success-stat-item">
              <span className="label">Critical Risks</span>
              <strong style={{ color: '#ef4444' }}>{successStats.critical}</strong>
            </div>
            <div className="success-stat-item">
              <span className="label">Covered Apps</span>
              <strong>{successStats.applications}</strong>
            </div>
          </div>
          <button className="btn-action btn-action--primary" onClick={() => navigate("/")} style={{ marginTop: '16px' }}>
            Go to Security Posture Command Center →
          </button>
        </div>
      )}

      {loading && (
        <div className="loading-overlay">
          <div className="spinner"></div>
          <div className="spinner-progress">
            <h3>{steps[currentStep]}</h3>
            <p>Running pipeline validation engines. Do not close this window.</p>
            <div className="progress-bar-container">
              <div
                className="progress-bar-fill"
                style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
              ></div>
            </div>
          </div>
        </div>
      )}

      <div className="upload-grid">
        <section className="upload-section">
          <h2>Required Datasets</h2>
          <div className="upload-cards-grid">
            {renderUploadCard('applications', 'json', true)}
            {renderUploadCard('dependencies', 'csv', true)}
            {renderUploadCard('vulnerabilities', 'json', true)}
            {renderUploadCard('licenses', 'json', true)}
          </div>
        </section>

        <section className="upload-section">
          <h2>Optional Datasets</h2>
          <div className="upload-cards-grid">
            {renderUploadCard('transitiveDependencies', 'json', false)}
            {renderUploadCard('labels', 'csv', false)}
          </div>
        </section>
      </div>

      <div className="action-row">
        <button
          className="btn-action btn-action--primary"
          onClick={handleAnalyze}
          disabled={loading}
        >
          {loading ? "Processing..." : "Analyze Ingested SBOM"}
        </button>

        <button
          className="btn-action"
          onClick={handleReset}
          disabled={loading}
          style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid rgba(239, 68, 68, 0.2)' }}
        >
          Reset to Sample Dataset
        </button>
      </div>
    </div>
  );
}
