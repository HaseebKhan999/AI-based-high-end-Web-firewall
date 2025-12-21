# AI-WAF Frontend

Modern React-based dashboard for the AI-powered Web Application Firewall (WAF) system.

## Features

- 📊 **Dashboard**: Real-time statistics, charts, and system status
- 📝 **Traffic Logs**: View and search through all HTTP requests
- 🛡️ **Attack Logs**: Monitor blocked requests and detected threats
- ✅ **Whitelist Management**: Manage trusted IP addresses
- ❌ **Blacklist Management**: Manage blocked IP addresses
- ⚙️ **Configuration**: Update WAF settings and thresholds
- 🤖 **ML Models**: View machine learning model metadata and performance

## Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Backend server running on `http://localhost:5000`

## Installation

1. Navigate to the frontend directory:
```bash
cd ai_waf_frontendcode
```

2. Install dependencies:
```bash
npm install
```

## Configuration

Create a `.env` file in the root directory (or use the default):
```env
VITE_API_BASE_URL=http://localhost:5000
```

## Running the Application

### Development Mode

Start the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

### Production Build

Build for production:
```bash
npm run build
```

Preview the production build:
```bash
npm run preview
```

## Project Structure

```
ai_waf_frontendcode/
├── src/
│   ├── components/          # Reusable components
│   │   ├── Layout.jsx       # Main layout with sidebar
│   │   └── Layout.css
│   ├── pages/               # Page components
│   │   ├── Dashboard.jsx
│   │   ├── TrafficLogs.jsx
│   │   ├── AttackLogs.jsx
│   │   ├── Whitelist.jsx
│   │   ├── Blacklist.jsx
│   │   ├── Configuration.jsx
│   │   └── MLModels.jsx
│   ├── services/            # API services
│   │   └── api.js           # API client
│   ├── App.jsx              # Main app component
│   ├── main.jsx             # Entry point
│   └── index.css            # Global styles
├── index.html
├── package.json
├── vite.config.js
└── README.md
```

## API Integration

The frontend integrates with the following backend endpoints:

### Admin API (`/api/admin`)
- `GET /stats` - Dashboard statistics
- `GET /logs` - Traffic logs with pagination
- `GET /logs/:id` - Log details
- `GET /attacks` - Attack logs
- `GET /whitelist` - Get whitelist
- `POST /whitelist` - Add to whitelist
- `DELETE /whitelist/:ip` - Remove from whitelist
- `GET /blacklist` - Get blacklist
- `POST /blacklist` - Add to blacklist
- `DELETE /blacklist/:ip` - Remove from blacklist
- `GET /config` - Get configuration
- `PUT /config` - Update configuration
- `GET /models` - Get ML models

## Features Overview

### Dashboard
- Real-time statistics cards
- Attack type distribution chart
- Top attackers bar chart
- System status indicators
- Recent activity feed

### Traffic Logs
- Searchable log table
- Pagination support
- Detailed log view modal
- Threat score visualization
- Filter by status

### Attack Logs
- Card-based attack display
- Attack type badges
- Threat score indicators
- IP address tracking

### Whitelist/Blacklist
- Add/remove IP addresses
- Reason tracking
- Expiration dates (blacklist)
- Table view with actions

### Configuration
- Update threat threshold
- Toggle features (blocking, logging, rate limiting)
- Real-time validation
- Change indicators

### ML Models
- Model metadata display
- Accuracy metrics
- Performance indicators
- File path information

## Technologies Used

- **React 18** - UI framework
- **React Router** - Routing
- **Axios** - HTTP client
- **Recharts** - Data visualization
- **React Icons** - Icon library
- **Vite** - Build tool
- **date-fns** - Date formatting

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Troubleshooting

### Backend Connection Issues

If you see connection errors:
1. Ensure the backend server is running on `http://localhost:5000`
2. Check CORS settings in the backend
3. Verify the API base URL in `.env`

### Port Already in Use

If port 3000 is already in use:
- Change the port in `vite.config.js`:
```js
server: {
  port: 3001, // Change to available port
}
```

## Development Notes

- The frontend uses Vite for fast development
- Hot module replacement (HMR) is enabled
- API calls are proxied through Vite dev server
- All API endpoints are configured in `src/services/api.js`

## License

Part of the AI-WAF project.

