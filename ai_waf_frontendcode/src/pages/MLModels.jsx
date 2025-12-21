import React, { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { formatDateGMT5 } from '../utils/dateUtils';
import { FiCpu, FiRefreshCw, FiCheckCircle, FiAlertCircle } from 'react-icons/fi';
import './MLModels.css';

const MLModels = () => {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchModels();
  }, []);

  const fetchModels = async () => {
    try {
      setLoading(true);
      const response = await adminAPI.getModels();
      setModels(response.data.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to load ML models');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return formatDateGMT5(dateString);
  };

  const getAccuracyColor = (accuracy) => {
    if (accuracy >= 0.9) return '#10b981';
    if (accuracy >= 0.7) return '#f59e0b';
    return '#ef4444';
  };

  return (
    <div className="ml-models-page">
      <div className="models-header">
        <div className="models-title-section">
          <FiCpu className="models-icon" />
          <div>
            <h2>ML Models</h2>
            <p className="models-subtitle">Machine Learning models for threat detection</p>
          </div>
        </div>
        <button onClick={fetchModels} className="refresh-btn">
          <FiRefreshCw /> Refresh
        </button>
      </div>

      {loading ? (
        <div className="loading">Loading ML models...</div>
      ) : error ? (
        <div className="error">Error: {error}</div>
      ) : models.length === 0 ? (
        <div className="no-models">
          <FiCpu className="no-models-icon" />
          <h3>No ML Models Found</h3>
          <p>ML models will appear here once they are trained and loaded.</p>
        </div>
      ) : (
        <div className="models-grid">
          {models.map((model) => (
            <div key={model.id} className="model-card">
              <div className="model-card-header">
                <div className="model-name-section">
                  <FiCpu className="model-icon" />
                  <div>
                    <h3 className="model-name">{model.model_name || 'Unknown Model'}</h3>
                    <p className="model-version">Version {model.model_version || 'N/A'}</p>
                  </div>
                </div>
                {model.accuracy !== null && model.accuracy !== undefined && (
                  <div 
                    className="accuracy-badge"
                    style={{
                      backgroundColor: `${getAccuracyColor(model.accuracy)}20`,
                      color: getAccuracyColor(model.accuracy)
                    }}
                  >
                    {(model.accuracy * 100).toFixed(1)}%
                  </div>
                )}
              </div>
              <div className="model-card-body">
                <div className="model-info-item">
                  <span className="model-info-label">Accuracy:</span>
                  <span 
                    className="model-info-value"
                    style={{ color: getAccuracyColor(model.accuracy || 0) }}
                  >
                    {model.accuracy !== null && model.accuracy !== undefined
                      ? `${(model.accuracy * 100).toFixed(2)}%`
                      : 'N/A'}
                  </span>
                </div>
                {model.file_path && (
                  <div className="model-info-item">
                    <span className="model-info-label">File Path:</span>
                    <span className="model-info-value file-path">{model.file_path}</span>
                  </div>
                )}
                {model.description && (
                  <div className="model-info-item">
                    <span className="model-info-label">Description:</span>
                    <span className="model-info-value">{model.description}</span>
                  </div>
                )}
                <div className="model-info-item">
                  <span className="model-info-label">Created At:</span>
                  <span className="model-info-value">{formatDate(model.created_at)}</span>
                </div>
              </div>
              <div className="model-card-footer">
                {model.accuracy !== null && model.accuracy !== undefined && (
                  <div className="model-status">
                    {model.accuracy >= 0.9 ? (
                      <>
                        <FiCheckCircle className="status-icon success" />
                        <span>Excellent Performance</span>
                      </>
                    ) : model.accuracy >= 0.7 ? (
                      <>
                        <FiAlertCircle className="status-icon warning" />
                        <span>Good Performance</span>
                      </>
                    ) : (
                      <>
                        <FiAlertCircle className="status-icon error" />
                        <span>Needs Improvement</span>
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default MLModels;

