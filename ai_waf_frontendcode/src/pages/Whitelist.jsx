import React, { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { formatDateGMT5 } from '../utils/dateUtils';
import { FiPlus, FiTrash2, FiRefreshCw, FiCheckCircle } from 'react-icons/fi';
import './Whitelist.css';

const Whitelist = () => {
  const [whitelist, setWhitelist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newIP, setNewIP] = useState('');
  const [newReason, setNewReason] = useState('');
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    fetchWhitelist();
  }, []);

  const fetchWhitelist = async () => {
    try {
      setLoading(true);
      const response = await adminAPI.getWhitelist();
      setWhitelist(response.data.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to load whitelist');
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
      await adminAPI.addToWhitelist(newIP.trim(), newReason.trim() || 'Manual addition', 'admin');
      setNewIP('');
      setNewReason('');
      setShowAddModal(false);
      fetchWhitelist();
    } catch (err) {
      alert('Failed to add IP to whitelist: ' + (err.response?.data?.error || err.message));
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (ipAddress) => {
    if (!window.confirm(`Are you sure you want to remove ${ipAddress} from the whitelist?`)) {
      return;
    }

    try {
      await adminAPI.removeFromWhitelist(ipAddress);
      fetchWhitelist();
    } catch (err) {
      alert('Failed to remove IP from whitelist: ' + (err.response?.data?.error || err.message));
    }
  };

  const formatDate = (dateString) => {
    return formatDateGMT5(dateString);
  };

  return (
    <div className="whitelist-page">
      <div className="whitelist-header">
        <div className="whitelist-title-section">
          <FiCheckCircle className="whitelist-icon" />
          <div>
            <h2>IP Whitelist</h2>
            <p className="whitelist-subtitle">Trusted IP addresses that bypass WAF checks</p>
          </div>
        </div>
        <div className="whitelist-actions">
          <button onClick={fetchWhitelist} className="refresh-btn">
            <FiRefreshCw /> Refresh
          </button>
          <button onClick={() => setShowAddModal(true)} className="add-btn">
            <FiPlus /> Add IP
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading">Loading whitelist...</div>
      ) : error ? (
        <div className="error">Error: {error}</div>
      ) : (
        <div className="whitelist-table-container">
          {whitelist.length === 0 ? (
            <div className="no-data">
              <FiCheckCircle className="no-data-icon" />
              <h3>No Whitelisted IPs</h3>
              <p>Add IP addresses to allow them to bypass WAF protection</p>
            </div>
          ) : (
            <table className="whitelist-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Reason</th>
                  <th>Added By</th>
                  <th>Created At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {whitelist.map((item) => (
                  <tr key={item.id}>
                    <td className="ip-address">{item.ip_address}</td>
                    <td>{item.reason || '-'}</td>
                    <td>{item.added_by || 'admin'}</td>
                    <td>{formatDate(item.created_at)}</td>
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
              <h2>Add IP to Whitelist</h2>
              <button className="modal-close" onClick={() => setShowAddModal(false)}>×</button>
            </div>
            <form onSubmit={handleAdd} className="modal-form">
              <div className="form-group">
                <label>IP Address *</label>
                <input
                  type="text"
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  placeholder="192.168.1.1"
                  required
                  className="form-input"
                />
              </div>
              <div className="form-group">
                <label>Reason</label>
                <textarea
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  placeholder="Reason for whitelisting this IP..."
                  rows="3"
                  className="form-textarea"
                />
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

export default Whitelist;

