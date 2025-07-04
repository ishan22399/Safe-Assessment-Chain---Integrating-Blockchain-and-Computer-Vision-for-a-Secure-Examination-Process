# Safe-Assessment-Chain: Integrating Blockchain and Computer Vision for a Secure Examination Process

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://choosealicense.com/licenses/mit/) [![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/) [![Flask](https://img.shields.io/badge/Flask-2.1.3-green.svg)](https://flask.palletsprojects.com/)

---

## Table of Contents
- [Project Title](#safe-assessment-chain-integrating-blockchain-and-computer-vision-for-a-secure-examination-process)
- [Description](#description)
- [Motivation](#motivation)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

---

## Description
Safe-Assessment-Chain is a secure, multitenant online examination platform that leverages blockchain technology for tamper-proof exam records and computer vision for enhanced exam security. The system is built using Flask, SQLAlchemy, and Web3.py, and integrates with Ethereum-compatible blockchains (e.g., Ganache for local development).

## Motivation
- To address the growing need for secure, transparent, and tamper-proof online assessments.
- To provide a scalable solution for educational institutions to conduct exams with integrity.
- To leverage blockchain for auditability and computer vision for future proctoring enhancements.

## What Problem Does It Solve?
- Prevents exam result tampering and fraud by logging all critical actions on the blockchain.
- Enables certificate verification for employers and institutions.
- Supports multiple tenants (colleges/universities) in a single deployment.

## What Makes This Project Stand Out?
- Blockchain-backed audit trail for all exam actions.
- Modular, multitenant architecture.
- Future-ready for computer vision-based proctoring.
- CLI tools for easy tenant and admin setup.

## Features
- **Multitenancy:** Supports multiple institutions (tenants) with isolated data.
- **User Roles:** Admin, Student, and Examiner roles with dedicated dashboards.
- **Blockchain Integration:** Logs critical actions (exam creation, registration, result publication) on the blockchain for transparency and verification.
- **MCQ Management:** Admins can create, edit, and delete exams and MCQs.
- **Student Registration:** Students can register for exams, take exams, and view results.
- **Result Publication:** Admins can publish results, which are then verifiable on the blockchain.
- **Query System:** Students can contact admins; admins can respond to queries.
- **Certificate Verification:** Publicly verify exam certificates using blockchain transaction hashes.
- **Computer Vision (Planned):** Integrate proctoring and face recognition for secure exam environments (future scope).

## Tech Stack
- **Backend:** Python, Flask, Flask-SQLAlchemy, Flask-Migrate
- **Blockchain:** Ethereum (Ganache for local), Web3.py
- **Frontend:** HTML, CSS, JavaScript (Jinja2 templates)
- **Database:** SQLite (default, can be changed)

## Installation
### Prerequisites
- Python 3.8+
- Ganache (for local blockchain)
- Node.js (for Ganache CLI, if needed)

### Steps
1. **Clone the repository:**
   ```sh
   git clone <repo-url>
   cd edi5
   ```
2. **Install Python dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. **Start Ganache and deploy the smart contract.**
   - Update `CONTRACT_ADDRESS` and ABI as needed in `app.py`.
4. **Initialize the database:**
   ```sh
   flask db upgrade
   ```
5. **Run the Flask app:**
   ```sh
   flask run
   ```

## Usage
- Access the app at `http://127.0.0.1:5000/`.
- Register as a new tenant and admin using the CLI command:
  ```sh
  flask create-tenant
  ```
- Admins can add exams, set MCQs, schedule exams, and publish results.
- Students can register, enroll in exams, take exams, and view results.
- Blockchain logs and certificate verification are available from the admin dashboard.

## Screenshots
<!-- Add screenshots/gifs of your app UI here -->

## Project Structure
- `app.py` - Main Flask application
- `contracts/` - Solidity smart contracts
- `templates/` - HTML templates
- `static/` - CSS and JS files
- `migrations/` - Database migration scripts
- `requirements.txt` - Python dependencies

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for improvements or bug fixes. For major changes, please open an issue first to discuss what you would like to change.

## Credits
- Developed by [Your Name/Team].
- Special thanks to the open-source community and the following tools:
  - Flask, SQLAlchemy, Web3.py, Ganache, and more.
- Inspired by best practices in secure online assessment.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

> _Every day is a learning day. Keep your README up-to-date and make your project stand out!_
