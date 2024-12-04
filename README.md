# Safe Assessment Chain

**Integrating Blockchain and Computer Vision for a Secure Examination Process**
![3d-rendering-blockchain-technology](https://github.com/user-attachments/assets/3e47bef4-d1c6-4bf3-8591-fa284742b0a3)

---

## Overview

The **Safe Assessment Chain** is a cutting-edge project combining blockchain technology and computer vision to create a secure and transparent examination process. This system addresses common challenges in traditional examination systems, such as cheating, identity verification, and result manipulation, by leveraging Ethereum smart contracts and AI-powered facial recognition.

---

## Features

- **Blockchain-Based Security**: Ensures immutable records of examination data and results using Ethereum smart contracts.
- **Computer Vision**: Integrates AI-driven facial recognition for identity verification and real-time monitoring.
- **Transparent Exam Management**: Simplifies exam registration, attendance, and result handling with decentralized systems.
- **Scalability**: Designed for small to large-scale examination environments.

---

## Project Structure

### **Folders and Files**

- **`static/`**: Contains static assets like CSS, JavaScript, and images.
- **`templates/`**: HTML templates for the web interface.
- **`StudReg.sol`**: Smart contract for student registration.
- **`ExamAdd.sol`**: Smart contract for adding and managing exams.
- **`UserAuth.sol`**: Smart contract for user authentication and role management.
- **`TransactionHandler_abi.json`**: ABI file for blockchain interaction.
- **`TransactionHandler_bytecode.txt`**: Bytecode for blockchain transactions.
- **`app.py`**: Flask application managing the backend logic.
- **`config.py`**: Configuration file for the Flask app and blockchain connection.
- **`database.db`**: SQLite database for storing auxiliary data.
- **`requirements.txt`**: Python dependencies required for the project.

---

## Prerequisites

1. **Python (3.9 or higher)**  
   Ensure Python is installed on your system.
2. **Node.js and npm**  
   Required for smart contract deployment and testing.
3. **Ethereum Development Tools**  
   Install Ganache and Truffle Suite for a local blockchain environment.
4. **Python Libraries**: Install using `requirements.txt`.

   ```bash
   pip install -r requirements.txt
