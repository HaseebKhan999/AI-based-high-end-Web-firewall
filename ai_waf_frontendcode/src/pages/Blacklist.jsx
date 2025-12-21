import React, { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { formatDateGMT5 } from '../utils/dateUtils';
import { FiPlus, FiTrash2, FiRefreshCw, FiXCircle } from 'react-icons/fi';
import './Blacklist.css';

const Blacklist = () => {
  const [blacklist, setBlacklist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newIP, setNewIP] = useState('');
  const [newReason, setNewReason] = useState('');
  const [expiresHours, setExpiresHours] = useState('');
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    fetchBlacklist();
  }, []);

  const fetchBlacklist = async () => {
    try {
      setLoading(true);
      const response = await adminAPI.getBlacklist();
      setBlacklist(response.data.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to load blacklist');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!newIP.trim()) {
      alert('Please enter an IP address');
      return;
    }

    try {
      setAdding(true);
      await adminAPI.addToBlacklist(
        newIP.trim(),
        newReason.trim() || 'Manual addition',
        'admin',
        expiresHours ? parseInt(expiresHours) : null
      );
      setNewIP('');
      setNewReason('');
      setExpiresHours('');
      setShowAddModal(false);
      fetchBlacklist();
    } catch (err) {
      alert('Failed to add IP to blacklist: ' + (err.response?.data?.error || err.message));
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (ipAddress) => {
    if (!window.confirm(`Are you sure you want to remove ${ipAddress} from the blacklist?`)) {
      return;
    }

    try {
      await adminAPI.removeFromBlacklist(ipAddress);
      fetchBlacklist();
    } catch (err) {
      alert('Failed to remove IP from blacklist: ' + (err.response?.data?.error || err.message));
    }
  };

  const formatDate = (dateString) => {
    return formatDateGMT5(dateString);
  };

  const isExpired = (expiresAt) => {
    if (!expiresAt) return false;
    return new Date(expiresAt) < new Date();
  };

  return (
    <div className="blacklist-page">
      <div className="blacklist-header">
        <div className="blacklist-title-section">
          <FiXCircle className="blacklist-icon" />
          <div>
            <h2>IP Blacklist</h2>
            <p className="blacklist-subtitle">Blocked IP addresses that are denied access</p>
          </div>
        </div>
        <div className="blacklist-actions">
          <button onClick={fetchBlacklist} className="refresh-btn">
            <FiRefreshCw /> Refresh
          </button>
          <button onClick={() => setShowAddModal(true)} className="add-btn">
            <FiPlus /> Add IP
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading">Loading blacklist...</div>
      ) : error ? (
        <div className="error">Error: {error}</div>
      ) : (
        <div className="blacklist-table-container">
          {blacklist.length === 0 ? (
            <div className="no-data">
              <FiXCircle className="no-data-icon" />
              <h3>No Blacklisted IPs</h3>
              <p>Add IP addresses to block them from accessing your system</p>
            </div>
          ) : (
            <table className="blacklist-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Reason</th>
                  <th>Added By</th>
                  <th>Created At</th>
                  <th>Expires At</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {blacklist.map((item) => (
                  <tr key={item.id} className={isExpired(item.expires_at) ? 'expired' : ''}>
                    <td className="ip-address">{item.ip_address}</td>
                    <td>{item.reason || '-'}</td>
                    <td>{item.added_by || 'admin'}</td>
                    <td>{formatDate(item.created_at)}</td>
                    <td>{item.expires_at ? formatDate(item.expires_at) : 'Permanent'}</td>
                    <td>
                      {isExpired(item.expires_at) ? (
                        <span className="status-badge expired-badge">Expired</span>
                      ) : (
                        <span className="status-badge active-badge">Active</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="remove-btn"
                        onClick={() => handleRemove(item.ip_address)}
                      >
                        <FiTrash2 /> Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Add IP to Blacklist</h2>
              <button className="modal-close" onClick={() => setShowAddModal(false)}>×</button>
            </div>
            <form onSubmit={handleAdd} className="modal-form">
              <div className="form-group">
                <label>IP Address *</label>
                <input
                  type="text"
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  placeholder="10.0.0.1"
                  required
                  className="form-input"
                />
              </div>
              <div className="form-group">
                <label>Reason</label>
                <textarea
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  placeholder="Reason for blacklisting this IP..."
                  rows="3"
                  className="form-textarea"
                />
              </div>
              <div className="form-group">
                <label>Expires After (Hours)</label>
                <input
                  type="number"
                  value={expiresHours}
                  onChange={(e) => setExpiresHours(e.target.value)}
                  placeholder="Leave empty for permanent"
                  min="1"
                  className="form-input"
                />
                <small className="form-hint">Leave empty to make it permanent</small>
              </div>
              <div className="form-actions">
                <button type="button" onClick={() => setShowAddModal(false)} className="cancel-btn">
                  Cancel
                </button>
                <button type="submit" disabled={adding} className="submit-btn">
                  {adding ? 'Adding...' : 'Add IP'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Blacklist;

