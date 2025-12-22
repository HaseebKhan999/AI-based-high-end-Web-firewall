import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  FiLayout, FiActivity, FiShield, FiAlertTriangle, 
  FiCheckCircle, FiXCircle, FiSettings, FiCpu,
  FiMenu, FiX 
} from 'react-icons/fi';
import { 
  MdDashboard, MdSecurity, MdTraffic, 
  MdWarning, MdVerified, MdBlock 
} from 'react-icons/md';
import { 
  RiShieldCheckLine, RiShieldCrossLine 
} from 'react-icons/ri';
import './Layout.css';

const Layout = ({ children }) => {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const menuItems = [
    { path: '/dashboard', icon: MdDashboard, label: 'Dashboard', gradient: 'from-blue-500 to-cyan-500' },
    { path: '/traffic-logs', icon: FiActivity, label: 'Traffic Logs', gradient: 'from-green-500 to-emerald-500' },
    { path: '/attack-logs', icon: MdWarning, label: 'Attack Logs', gradient: 'from-red-500 to-orange-500' },
    { path: '/whitelist', icon: RiShieldCheckLine, label: 'Whitelist', gradient: 'from-green-400 to-teal-400' },
    { path: '/blacklist', icon: RiShieldCrossLine, label: 'Blacklist', gradient: 'from-red-400 to-pink-500' },
    { path: '/configuration', icon: FiSettings, label: 'Configuration', gradient: 'from-purple-500 to-indigo-500' },
    { path: '/ml-models', icon: FiCpu, label: 'ML Models', gradient: 'from-violet-500 to-purple-600' },
  ];

  return (
    <div className="layout">
      <aside className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`}>
        <div className="sidebar-header">
          <div className="logo">
            <div className="logo-icon-wrapper">
              <FiShield className="logo-icon" />
              <div className="logo-icon-glow"></div>
            </div>
            <span className="logo-text">
              <span className="logo-ai">AI</span>
              <span className="logo-separator">-</span>
              <span className="logo-waf">WAF</span>
            </span>
          </div>
          <button 
            className="sidebar-toggle"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? <FiX /> : <FiMenu />}
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

