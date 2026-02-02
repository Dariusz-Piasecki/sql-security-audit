# SQL Case Study: Organizational Security Analysis

## Project Overview
In this project, I acted as a Security Professional tasked with investigating potential security incidents by analyzing database logs. Using **SQL in DB Browser for SQLite**, I performed data filtering to identify suspicious login patterns and audit employee access across different departments. This analysis helps enhance the organization’s security posture by pinpointing potential vulnerabilities.

## Database Schema
The analysis was performed on two primary tables:
* `log_in_attempts`: Tracking user access, timestamps, origin countries, and success/failure status.
* `employees`: Managing organizational data, department assignments, and office locations.

![Database Structure](Screenshot%202026-02-02%20at%2013.29.32.png)

---

## 🔍 Investigation Tasks

### 1. After-Hours Failed Login Attempts
**Objective:** Identify unauthorized access attempts occurring after business hours (18:00).
```sql
SELECT username, login_date, login_time, country 
FROM log_in_attempts 
WHERE login_time > '18:00:00' AND success = 0;
