import React, { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { formatDateGMT5 } from '../utils/dateUtils';
import { FiSearch, FiRefreshCw, FiEye, FiChevronLeft, FiChevronRight } from 'react-icons/fi';
import './TrafficLogs.css';

const TrafficLogs = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [selectedLog, setSelectedLog] = useState(null);

  useEffect(() => {
    fetchLogs();
  }, [offset]);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const response = await adminAPI.getLogs(limit, offset);
      setLogs(response.data.data || []);
      setTotal(response.data.pagination?.total || 0);
      setError(null);
    } catch (err) {
      setError('Failed to load traffic logs');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const fetchLogDetails = async (logId) => {
    try {
      const response = await adminAPI.getLogDetails(logId);
      setSelectedLog(response.data.data);
    } catch (err) {
      console.error('Failed to load log details:', err);
    }
  };

  const filteredLogs = logs.filter(log => {
    const searchLower = searchTerm.toLowerCase();
    return (
      log.ip_address?.toLowerCase().includes(searchLower) ||
      log.url?.toLowerCase().includes(searchLower) ||
      log.method?.toLowerCase().includes(searchLower) ||
      log.attack_type?.toLowerCase().includes(searchLower)
    );
  });

  const getThreatColor = (score) => {
    if (score >= 0.7) return '#ef4444';
    if (score >= 0.4) return '#f59e0b';
    return '#10b981';
  };

  const formatDate = (dateString) => {
    return formatDateGMT5(dateString);
  };

  return (
    <div className="traffic-logs">
      <div className="logs-header">
        <div className="search-box">
          <FiSearch className="search-icon" />
          <input
            type="text"
            placeholder="Search by IP, URL, method, or attack type..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>
        <button onClick={fetchLogs} className="refresh-btn">
          <FiRefreshCw /> Refresh
        </button>
      </div>

      {loading && logs.length === 0 ? (
        <div className="loading">Loading traffic logs...</div>
      ) : error ? (
        <div className="error">Error: {error}</div>
      ) : (
        <>
          <div className="logs-table-container">
            <table className="logs-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>IP Address</th>
                  <th>Method</th>
                  <th>URL</th>
                  <th>Threat Score</th>
                  <th>Status</th>
                  <th>Attack Type</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="no-data">No logs found</td>
                  </tr>
                ) : (
                  filteredLogs.map((log) => (
                    <tr key={log.id} className={log.is_blocked ? 'blocked' : ''}>
                      <td>{formatDate(log.timestamp)}</td>
                      <td className="ip-address">{log.ip_address}</td>
                      <td>
                        <span className={`method-badge method-${log.method?.toLowerCase()}`}>
                          {log.method}
                        </span>
                      </td>
                      <td className="url-cell" title={log.url}>
                        {log.url?.substring(0, 50)}
                        {log.url?.length > 50 && '...'}
                      </td>
                      <td>
                        <div className="threat-score">
                          <div
                            className="threat-bar"
                            style={{
                              width: `${(log.threat_score || 0) * 100}%`,
                              backgroundColor: getThreatColor(log.threat_score || 0)
                            }}
                          />
                          <span className="threat-value">
                            {(log.threat_score || 0).toFixed(2)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className={`status-badge ${log.is_blocked ? 'blocked' : 'allowed'}`}>
                          {log.is_blocked ? 'Blocked' : 'Allowed'}
                        </span>
                      </td>
                      <td>{log.attack_type || '-'}</td>
                      <td>
                        <button
                          className="view-btn"
                          onClick={() => fetchLogDetails(log.id)}
                        >
                          <FiEye /> View
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="pagination-btn"
            >
              <FiChevronLeft /> Previous
            </button>
            <span className="pagination-info">
              Showing {offset + 1} - {Math.min(offset + limit, total)} of {total}
            </span>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="pagination-btn"
            >
              Next <FiChevronRight />
            </button>
          </div>
        </>
      )}

      {selectedLog && (
        <div className="modal-overlay" onClick={() => setSelectedLog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Log Details</h2>
              <button className="modal-close" onClick={() => setSelectedLog(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-section">
                <h3>Request Information</h3>
                <div className="detail-grid">
                  <div className="detail-item">
                    <label>ID:</label>
                    <span>{selectedLog.id}</span>
                  </div>
                  <div className="detail-item">
                    <label>Timestamp:</label>
                    <span>{formatDate(selectedLog.timestamp)}</span>
                  </div>
                  <div className="detail-item">
                    <label>IP Address:</label>
                    <span>{selectedLog.ip_address}</span>
                  </div>
                  <div className="detail-item">
                    <label>Method:</label>
                    <span>{selectedLog.method}</span>
                  </div>
                  <div className="detail-item">
                    <label>URL:</label>
                    <span className="detail-url">{selectedLog.url}</span>
                  </div>
                  <div className="detail-item">
                    <label>Threat Score:</label>
                    <span style={{ color: getThreatColor(selectedLog.threat_score || 0) }}>
                      {(selectedLog.threat_score || 0).toFixed(4)}
                    </span>
                  </div>
                  <div className="detail-item">
                    <label>Status:</label>
                    <span className={`status-badge ${selectedLog.is_blocked ? 'blocked' : 'allowed'}`}>
                      {selectedLog.is_blocked ? 'Blocked' : 'Allowed'}
                    </span>
                  </div>
                  <div className="detail-item">
                    <label>Attack Type:</label>
                    <span>{selectedLog.attack_type || 'None'}</span>
                  </div>
                </div>
              </div>
              {selectedLog.headers && (
                <div className="detail-section">
                  <h3>Headers</h3>
                  <pre className="detail-pre">{JSON.stringify(selectedLog.headers, null, 2)}</pre>
                </div>
              )}
              {selectedLog.body && (
                <div className="detail-section">
                  <h3>Body</h3>
                  <pre className="detail-pre">{selectedLog.body}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TrafficLogs;

