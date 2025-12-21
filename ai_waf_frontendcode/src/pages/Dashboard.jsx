import React, { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import { formatDateGMT5 } from '../utils/dateUtils';
import { 
  FiActivity, FiShield, FiAlertTriangle, FiTrendingUp,
  FiClock, FiGlobe, FiCheckCircle, FiXCircle
} from 'react-icons/fi';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import './Dashboard.css';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await adminAPI.getStats();
      setStats(response.data.data);
      setError(null);
    } catch (err) {
      setError('Failed to load statistics');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (loading && !stats) {
    return <div className="loading">Loading dashboard...</div>;
  }

  if (error && !stats) {
    return <div className="error">Error: {error}</div>;
  }

  const statCards = [
    {
      title: 'Total Requests',
      value: stats?.total_requests || 0,
      icon: FiActivity,
      color: '#3b82f6',
      change: '+12%'
    },
    {
      title: 'Blocked Requests',
      value: stats?.blocked_requests || 0,
      icon: FiShield,
      color: '#ef4444',
      change: `+${stats?.blocked_requests || 0}`
    },
    {
      title: 'Requests (24h)',
      value: stats?.requests_24h || 0,
      icon: FiClock,
      color: '#10b981',
      change: '+5%'
    },
    {
      title: 'Attacks (24h)',
      value: stats?.attacks_24h || 0,
      icon: FiAlertTriangle,
      color: '#f59e0b',
      change: `+${stats?.attacks_24h || 0}`
    },
  ];

  const attackTypesData = stats?.attack_types?.map(type => ({
    name: type.attack_type || 'Unknown',
    value: type.count || 0
  })) || [];

  const topAttackersData = stats?.top_attackers?.slice(0, 5).map(attacker => ({
    ip: attacker.ip_address,
    attacks: attacker.attack_count || 0
  })) || [];

  const COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6'];

  return (
    <div className="dashboard">
      <div className="stats-grid">
        {statCards.map((card, index) => {
          const Icon = card.icon;
          return (
            <div key={index} className="stat-card">
              <div className="stat-card-header">
                <div className="stat-card-icon" style={{ backgroundColor: `${card.color}20`, color: card.color }}>
                  <Icon />
                </div>
                <span className="stat-card-change" style={{ color: card.color }}>
                  {card.change}
                </span>
              </div>
              <div className="stat-card-content">
                <h3 className="stat-card-value">{card.value.toLocaleString()}</h3>
                <p className="stat-card-title">{card.title}</p>
              </div>
            </div>
          );
        })}
      </div>

      <div className="charts-grid">
        <div className="chart-card">
          <h3 className="chart-title">Attack Types Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={attackTypesData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {attackTypesData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3 className="chart-title">Top Attackers</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={topAttackersData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="ip" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="attacks" fill="#ef4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="info-grid">
        <div className="info-card">
          <h3 className="info-card-title">System Status</h3>
          <div className="info-list">
            <div className="info-item">
              <FiCheckCircle className="info-icon success" />
              <span>WAF Protection: Enabled</span>
            </div>
            <div className="info-item">
              <FiCheckCircle className="info-icon success" />
              <span>ML Detection: Active</span>
            </div>
            <div className="info-item">
              <FiCheckCircle className="info-icon success" />
              <span>Database: Connected</span>
            </div>
            <div className="info-item">
              <span className="info-label">Average Threat Score:</span>
              <span className="info-value">
                {(stats?.avg_threat_score || 0).toFixed(2)}
              </span>
            </div>
          </div>
        </div>

        <div className="info-card">
          <h3 className="info-card-title">Recent Activity</h3>
          <div className="activity-list">
            {stats?.recent_activity?.slice(0, 5).map((activity, index) => (
              <div key={index} className="activity-item">
                <div className="activity-icon">
                  {activity.is_blocked ? (
                    <FiXCircle className="error" />
                  ) : (
                    <FiCheckCircle className="success" />
                  )}
                </div>
                <div className="activity-content">
                  <p className="activity-text">{activity.ip_address}</p>
                  <p className="activity-time">{formatDateGMT5(activity.timestamp)}</p>
                </div>
              </div>
            )) || (
              <p className="no-data">No recent activity</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;

