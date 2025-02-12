# Secure Database-as-a-Service for Healthcare Data

## Team Members  
- **Pingili Gayathri**  
- **Sai Sharan Eruventy**  
- **Naga Sudha Pavani Tirumalasetty**  

## GitHub Repository  
[Project Repository](https://github.com/GayathriPingili/DSP_Project/tree/main/pj)

## Introduction  
In recent years, Database-as-a-Service (DBaaS) has gained popularity as a cloud computing model, offering scalability and ease of use. However, security and privacy concerns remain a challenge. This project aims to develop a secure healthcare database system that ensures data confidentiality, access control, and query integrity. The system employs encryption techniques, user authentication mechanisms, and secure query verification.

## System Design  

### **Architecture Overview**  
The system comprises three main components:  

1. **Client-Side (User Interface):**  
   - A web-based UI allows users to log in and interact with the database.  
   - Users belong to two groups:  
     - **Group H (Healthcare Providers)**: Full access to all records.  
     - **Group R (Researchers)**: Restricted access; personal identifiers are anonymized.  
   - Sensitive fields (e.g., gender, age) are encrypted and decrypted only on the client-side.  

2. **Server-Side (Database & Logic):**  
   - Built using Flask (Python).  
   - Utilizes MySQL for data storage.  
   - Implements secure authentication, access control, and query validation.  

3. **Security Features:**  
   - **User Authentication:** Secure password hashing (bcrypt/Argon2).  
   - **Access Control:** Role-based access control (RBAC).  
   - **Data Confidentiality:** AES encryption for sensitive fields.  
   - **Query Integrity:** Uses HMAC and Merkle Trees for tamper detection.  

## Implementation of Security Features  

### **1. User Authentication**  
- Passwords are securely hashed before storage.  
- Login authentication compares hashed passwords.  

### **2. Access Control**  
- **Group H:** Can view and modify all data.  
- **Group R:** Cannot access personal identifiers (e.g., first and last names).  

### **3. Query Integrity Protection**  
- **HMAC:** Ensures individual records have not been altered.  
- **Merkle Trees:** Guarantees completeness of query results.  

### **4. Data Confidentiality**  
- AES encryption secures sensitive fields (e.g., gender, age).  
- Decryption occurs only on the client-side for authorized users.  

### **5. Extra Feature: Order-Preserving Encryption (OPE)**  
- OPE allows range queries on encrypted numerical data (e.g., weight).  
- Enables secure queries like `SELECT * WHERE weight BETWEEN X AND Y`.  

## Contributions and Commit History  

| Team Member  | Role | Contributions |
|-------------|------|---------------|
| **Gayathri Pingili** | Frontend Developer | Developed UI components, login/dashboard pages |
| **Sai Sharan Eruventy** | Backend Developer | Implemented Flask API, authentication, access control |
| **Naga Sudha Pavani Tirumalasetty** | Security Specialist | Implemented AES encryption, HMAC, and Merkle Tree security |

## Limitations  
- **Performance Overhead:** Encryption/decryption may impact speed.  
- **Query Complexity:** Limited support for complex SQL joins on encrypted data.  
- **Cloud Trust Model:** Assumes a semi-trusted cloud environment.  

## Screenshots  
![image](https://github.com/user-attachments/assets/54581009-5fa5-4003-ab27-251314e788e0)

## Implementation Screenshots:

![image](https://github.com/user-attachments/assets/cd69d6fd-0cdd-46c1-9697-bbe8b285ce5b)

![image](https://github.com/user-attachments/assets/5c167d15-d22c-4ff4-adba-884ced8f9ba3)

![image](https://github.com/user-attachments/assets/3c6cc43a-909b-4b78-b2ca-ed4c7b0e234e)

![image](https://github.com/user-attachments/assets/c518a785-1ab7-42e2-b32d-b94cdc2a9774)

![image](https://github.com/user-attachments/assets/ce0b8d1d-fa15-4a4d-874a-f8c8b25d3c15)

![image](https://github.com/user-attachments/assets/ed49d5ec-f57a-4f82-8c49-55dc363ce0ff)

![image](https://github.com/user-attachments/assets/dd1d0fb8-9bd0-470e-b839-d4f2848f91ae)


## Conclusion  
This project successfully implements a secure healthcare database using encryption, authentication, and integrity verification techniques. Future work could enhance query capabilities and optimize encryption performance.  

---

💻 Developed as part of **[Kent State University]**  

