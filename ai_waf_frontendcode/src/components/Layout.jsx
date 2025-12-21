import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  FiLayout, FiActivity, FiShield, FiAlertTriangle, 
  FiCheckCircle, FiXCircle, FiSettings, FiCpu 
} from 'react-icons/fi';
import './Layout.css';

const Layout = ({ children }) => {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const menuItems = [
    { path: '/dashboard', icon: FiLayout, label: 'Dashboard' },
    { path: '/traffic-logs', icon: FiActivity, label: 'Traffic Logs' },
    { path: '/attack-logs', icon: FiShield, label: 'Attack Logs' },
    { path: '/whitelist', icon: FiCheckCircle, label: 'Whitelist' },
    { path: '/blacklist', icon: FiXCircle, label: 'Blacklist' },
    { path: '/configuration', icon: FiSettings, label: 'Configuration' },
    { path: '/ml-models', icon: FiCpu, label: 'ML Models' },
  ];

  return (
    <div className="layout">
      <aside className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`}>
        <div className="sidebar-header">
          <div className="logo">
            <FiShield className="logo-icon" />
            <span className="logo-text">AI-WAF</span>
          </div>
          <button 
            className="sidebar-toggle"
            onClick={() => setSidebarOpen(!sidebarOpen)}
          >
            {sidebarOpen ? '←' : '→'}
          </button>
        </div>
        <nav className="sidebar-nav">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon className="nav-icon" />
                {sidebarOpen && <span className="nav-label">{item.label}</span>}
              </Link>
            );
          })}
        </nav>
      </aside>
      <main className="main-content">
        <header className="top-header">
          <h1 className="page-title">
            {menuItems.find(item => item.path === location.pathname)?.label || 'Dashboard'}
          </h1>
        </header>
        <div className="content-wrapper">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;

