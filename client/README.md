# 🔍 DependLens

### Intelligent Software Supply Chain Risk Analyzer

DependLens transforms raw Software Bill of Materials (SBOM) data into actionable software supply-chain intelligence by identifying hidden dependency risks, prioritizing vulnerabilities, and generating remediation recommendations.

Modern applications rely heavily on third-party libraries. Vulnerabilities buried deep inside dependency trees, incompatible licenses, and abandoned packages create significant security and compliance risks. DependLens helps engineering teams detect, understand, and prioritize these risks before they become incidents.

---

## 🚀 Problem Statement

Software teams increasingly depend on open-source packages. However, organizations often struggle to answer critical questions:

- Which dependencies are vulnerable?
- Which risks are hidden inside transitive dependencies?
- Which licenses are legally incompatible with proprietary software?
- Which libraries are abandoned or unmaintained?
- Which issues should be fixed first?

DependLens provides a single platform to answer these questions.

---

## ✨ Features

| Feature | Description |
|----------|----------|
| 📂 SBOM Upload | Upload JSON and CSV datasets for analysis |
| 🔎 Vulnerability Detection | Match dependencies against CVE databases |
| 🌐 Transitive Dependency Resolution | Detect hidden vulnerabilities in nested dependency chains |
| ⚖️ License Analysis | Identify GPL, LGPL, and unknown-license risks |
| 🛠️ Maintenance Analysis | Flag libraries that have not been updated in years |
| 📊 Risk Scoring | Compute a composite supply-chain risk score |
| 🚨 Prioritization Engine | Classify risks into actionable categories |
| 🕸️ Dependency Graph | Visualize dependency relationships and attack paths |
| 🎯 Blast Radius Analysis | Measure how many applications are affected |
| 💡 Remediation Suggestions | Generate upgrade and mitigation recommendations |

---

## 🏗️ System Architecture

```text
SBOM Files (JSON / CSV)
            │
            ▼
     Ingestion Engine
            │
            ▼
    Dependency Graph Builder
            │
 ┌──────────┼──────────┐
 │          │          │
 ▼          ▼          ▼
Vulnerability Engine
License Engine
Maintenance Engine
 │          │          │
 └──────────┼──────────┘
            ▼
      Risk Scoring Engine
            ▼
    Prioritization Engine
            ▼
 Dashboard • Findings • Graph
            ▼
 Remediation & Insights
```

---

## 🧠 How DependLens Works

1. Upload SBOM files.
2. Parse applications and dependencies.
3. Build a dependency graph.
4. Resolve transitive dependencies.
5. Match packages against known vulnerabilities.
6. Analyze license compatibility.
7. Detect unmaintained libraries.
8. Compute risk scores.
9. Prioritize remediation.
10. Visualize results through dashboards and graphs.

---

## 🧪 Real-World Scenarios Handled

DependLens is designed to handle complex software supply-chain situations:

### Dependency Complexity

- Deep transitive dependency chains.
- Multiple paths to the same vulnerable package.
- Diamond dependencies.
- Multiple versions of the same library.
- Shared dependencies across applications.

### Vulnerability Context

- CVSS-based severity scoring.
- Patch availability analysis.
- Exploitability awareness.
- Vulnerabilities with and without fixes.
- Shared vulnerabilities across multiple applications.

### License Complexity

- GPL conflicts in proprietary applications.
- LGPL compatibility nuances.
- Unknown license risks.
- Dual-license scenarios.
- Compliance analysis.

### Maintenance Risk

- Abandoned libraries.
- Packages without recent updates.
- Deprecated dependencies.
- High-risk packages with no maintainers.

---

## 📊 Example Dependency Chain

```text
CustomerPortal
        │
        ▼
axios@0.21.0
        │
        ▼
lodash@4.17.15
```

DependLens detects:

- Vulnerability severity.
- Transitive risk exposure.
- Blast radius.
- Upgrade recommendations.
- Remediation priority.

---

## 🛠️ Tech Stack

### Frontend

- React
- Vite
- Tailwind CSS
- React Router

### Backend

- Node.js
- Express.js

### Data Processing

- PapaParse
- Multer

### Visualization

- React Flow
- Custom analytics components

### Data Formats

- JSON
- CSV

---

## 📁 Project Structure

```text
Dependlens/
│
├── frontend/
│   ├── src/
│   ├── components/
│   ├── pages/
│   └── services/
│
├── backend/
│   ├── src/
│   │   ├── ingestion/
│   │   ├── graph/
│   │   ├── vulnerability/
│   │   ├── license/
│   │   ├── maintenance/
│   │   ├── riskScore/
│   │   ├── prioritization/
│   │   └── validation/
│   │
│   ├── uploads/
│   └── server.js
│
└── README.md
```

---

## 📂 Supported Input Files

DependLens accepts:

### Required

- `applications.json`
- `sbom_dependencies.csv`
- `vulnerability_db.json`
- `license_rules.json`

### Optional

- `transitive_dependencies.json`
- `dependency_labels.csv`

---

## ⚙️ Installation

### Clone the repository

```bash
git clone https://github.com/Arunthathi23/Dependlens.git
cd Dependlens
```

### Backend setup

```bash
cd backend
npm install
npm run dev
```

Backend runs on:

```text
http://localhost:5000
```

### Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on:

```text
http://localhost:5173
```

---

## 📸 Screenshots

Add screenshots here:

### Dashboard

```text
docs/images/dashboard.png
```

### Dependency Graph

```text
docs/images/graph.png
```

### Findings

```text
docs/images/findings.png
```

### Upload Workflow

```text
docs/images/upload.png
```

---

## 🔮 Future Scope

- Live NVD integration.
- OSV integration.
- CI/CD pipeline support.
- GitHub Actions integration.
- Static code analysis.
- AI-powered exploit prediction.
- Automated pull-request remediation.

---

## 👥 Team

### Team Name

_Add your team name here._

### Members

- Hemadharsini P
- Arunthathi R

---

## 📜 License

This project was developed as part of a hackathon prototype and is intended for educational and research purposes.

---

## ⭐ Acknowledgements

DependLens was built to improve software supply-chain visibility and help teams proactively identify security, compliance, and maintenance risks hidden inside modern dependency ecosystems.