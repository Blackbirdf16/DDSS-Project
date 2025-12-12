# DDSS-Project

## FairRide – Secure Price Comparison Platform

FairRide is a security-driven ride price comparison system designed to demonstrate Secure Software Development and STDD principles. The application allows users to securely authenticate, submit trip requests, retrieve real-time ride prices from external providers, and compute the best available option in a transparent and auditable way.

The system prioritizes security from design to implementation by integrating access control, encryption, integrity validation, availability safeguards, and auditability into its core functionality. Each critical operation is implemented as a dedicated `_secure()` function and validated through automated tests that verify both functional correctness and security properties.

FairRide is intended as an educational reference project, showcasing how threat modeling, security patterns, and testing strategies can be systematically applied throughout the software development lifecycle.


Function 1 → Access control + confidentiality
Function 2 → Secure data handling + encryption
Function 3 → Integrity + availability + resilience
Function 4 → Transparency + auditability + fairness
1. authenticate_user()
2. create_trip_request_secure()
3. get_real_time_prices_secure()
4. compute_best_price_secure()

# Security-Driven Function Definition (SUD)

This section describes the core system functions of the FairRide application, each aligned with specific security objectives following the STDD approach.

---

## Function 1 – `authenticate_user()`

### Objective  
Ensure that only authorized users can access the FairRide system while protecting user credentials from disclosure, misuse, or impersonation.

### Domain Knowledge  
- Users authenticate using credentials  
- Credentials are sensitive data  
- Authentication precedes any system interaction  
- Sessions are established after successful login  

### Security Pattern  
**Access Control with Confidential Credential Handling**  
This pattern enforces authentication before access and protects credentials through secure handling mechanisms.

### Associated Tests  
- Reject access with invalid credentials  
- Reject access when credentials are missing  
- Ensure credentials are never exposed in logs  

---

## Function 2 – `create_trip_request_secure()`

### Objective  
Ensure that trip requests are created only by authenticated users and that sensitive trip data is securely handled and protected against leakage or manipulation.

### Domain Knowledge  
- TripRequest includes origin, destination, timestamp, and userId  
- Location data is sensitive  
- Only authenticated users may create trips  
- Trip data is securely stored  

### Security Pattern  
**Secure Data Handling with Encryption**  
This pattern ensures that trip data is validated and encrypted to prevent unauthorized access or disclosure.

### Associated Tests  
- Reject trip creation without authentication  
- Reject malformed or malicious trip input  
- Verify that sensitive trip data is not stored in plaintext  

---

## Function 3 – `get_real_time_prices_secure()`

### Objective  
Ensure that real-time price data obtained from external providers is accurate, available, and protected against manipulation or service disruption.

### Domain Knowledge  
- Prices are retrieved from multiple external providers  
- External data sources are untrusted  
- Price data must be continuously available  
- System must tolerate partial provider failures  

### Security Pattern  
**Integrity and Resilient Communication Pattern**  
This pattern ensures data integrity, availability, and resilience when interacting with external services.

### Associated Tests  
- Reject price data that fails integrity validation  
- Ensure system continues operating if a provider is unavailable  
- Detect and block abnormal or inconsistent price responses  

---

## Function 4 – `compute_best_price_secure()`

### Objective  
Ensure that the best ride price is computed in a transparent, auditable, and fair manner, preventing manipulation or biased outcomes.

### Domain Knowledge  
- Multiple validated price quotes are compared  
- Comparison logic must be deterministic  
- Results must be traceable and explainable  
- Users rely on the correctness of the result  

### Security Pattern  
**Auditable Decision and Transparency Pattern**  
This pattern ensures that price computation is traceable, verifiable, and free from hidden manipulation.

### Associated Tests  
- Verify that identical inputs produce identical outputs  
- Ensure the comparison process can be logged and audited  
- Detect and reject inconsistent or tampered input data  

---

## Summary

These four functions collectively cover access control, confidentiality, secure data handling, integrity, availability, resilience, transparency, and auditability.  
They ensure that security is integrated throughout the system’s design and development lifecycle in accordance with the STDD methodology.
