cat > README.md << 'EOF'
# AI-Based Web Application Firewall (WAF)

## Team Members
- Person 1: Traffic Interception & Feature Extraction
- Person 2: Database Management
- Person 3: ML Model Training & Inference
- Person 4: Frontend

## Project Structure
- `middleware/` - Request interception
- `utils/` - Utility functions
- `routes/` - API endpoints
- `database/` - Database layer
- `models/` - ML models
- `data/` - Datasets and trained models

## Setup Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
pip install -r requirement_p2.txt
```

### 2. Setup Database
```bash
# Create SQLite database
python config_db.py


### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your settings
```

### 4. Train ML Models (Person 3)
```bash
python models/train_model.py
python models/ml_model.py
python anonmaly_model.py
```

### 5. Run Application
```bash
python app.py
```

## API Endpoints
- `GET /api/admin/logs` - Get traffic logs
- `GET /api/admin/statistics` - Get attack statistics
- `POST /api/traffic/analyze` - Analyze request
EOF


## Run Frontend
npm install
npm run dev