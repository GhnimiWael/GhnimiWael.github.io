---
layout: post
title: OSEP (PEN-300) Review - OffSec Experienced Penetration Tester
categories:
- Red Team
- Pentest
- Offsec
- Certification
tags:
- Red Team
- Pentest
- Offsec
- OSEP
- PEN300
- Certification
date: 2024-11-10 20:00 +0100
description: A review of OSEP (PE-N300) Offsec Certification.
image: assets/img/certs/osep_b.png
---

# OffSec Experienced Penetration Tester (OSEP)
The OffSec Experienced Penetration Tester (OSEP) certification is a significant step in Advanced Penetration Testing. This certification targets professionals in mature security environments where the goal is often to bypass sophisticated defenses in relation to Active Directory concepts. The OSEP exam spans nearly two (2) full days (47 hours and 45 minutes), requiring candidates to reach a score of 100 points (`10 Flags`) to pass or reach the `secret.txt` flag, as second way to pass. Following the exam, candidates have an additional day to complete a report—a critical skill for any experienced penetration tester, covering both practical and analytical aspects of the role.

# PEN-300 Course Material
The Advanced Evasion Techniques and Breaching Defenses (PEN-300) course provides a wealth of information through detailed PDFs and videos, accompanied by hands-on exercises. After thoroughly reading the entire PEN-300 course and working through the associated labs, I moved on to the Challenge Labs to deepen my understanding. The course provides a massive amount of information through comprehensive PDFs (~740 Pages) and videos (+19 Hours) with practical exercises. Focusing on lab practice has been effective for retention, though some incomplete code snippets led to minor bugs or typos, which slowed my progress at times. Overall, the content is outstanding, even without bonus points.

I won’t dive into all the course details, as they’re easily searchable, but here’s a brief overview of what the PEN-300 course covers:

- Phishing and client-side attacks while evading antivirus
- AV evasion and bypassing Applocker
- Developing custom C# process injectors and hollowers
- Active Directory (AD) and MSSQL exploitation
- Windows and Linux lateral movement

The following topics are covered in the PEN-300 course:

1. Operating System and Programming Theory
2. Client Side Code Execution With Office
3. Client Side Code Execution With Jscript
4. Process Injection and Migration
5. Introduction to Antivirus Evasion
6. Advanced Antivirus Evasion
7. Application Whitelisting
8. Bypassing Network Filters
9. Linux Post-Exploitation
10. Kiosk Breakouts
11. Windows Credentials
12. Windows Lateral Movement
13. Linux Lateral Movement
14. Microsoft SQL Attacks
15. Active Directory Exploitation

Reading other students’ OSEP reviews was insightful, and since OSEP reviews are far less common than OSCP ones, I decided to share my own thoughts on passing the OSEP in 2024!

# PEN-300 Challenge Lab
The PEN-300 Challenge Lab presents a series of challenges designed to apply course concepts in realistic corporate scenarios. Since many exercises rely heavily on C# and the Win32 API, I’ve made sure to compile and debug all C# code from the course to ensure functionality. While some students may have shared compiled C# code on GitHub, I strongly recommend coding and compiling independently to gain a deep understanding of how each function works. 

The Challenge Lab emphasizes corporate environments with scenarios requiring post-exploitation tactics, such as dumping credentials after obtaining administrator or root access, performing lateral movement, and leveraging misconfigurations or credentialed access to navigate across systems. It also covers relationship mapping between machines and users, even extending to domain trust relationships.

For additional support, OffSec offers a dedicated Discord channel linked to the OffSec Training Library, providing students with a space to discuss challenges and seek assistance. The student admins are highly supportive, providing guidance when I’m stuck on particular topics.

# OffSec Experienced Penetration Tester Exam
The exam provides 47 hours and 45 minutes, which is sufficient to achieve the required 100 points. My approach was to start with the simplest steps, bearing in mind that corporate networks often have dependencies and multiple attack paths. Effective time management is crucial; balancing between broad exploration and in-depth analysis is essential. I recommend capturing screenshots and taking some notes along the way to avoid missing critical steps and jotting down rough notes to track progress. Preparing a report template beforehand also streamlines post-exam tasks.

I completed the core exam objective (finding the `secret.txt`) within 12 hours. After a 4-hour rest, I discovered an additional flag, bringing my total to 10 flags and the secret.txt. I then immediately started the reporting process, ensuring I had a solid record of all actions and findings.

# Resources
I’ve created a GitHub repository OSEP_Prep (<https://github.com/GhnimiWael/OSEP_Prep>) to share valuable `EXTERNAL` resources and links for those preparing for OffSec’s OSEP (PEN-300) certification. This repository includes curated content, tools, and references that I found useful during my study, aiming to help others efficiently navigate the vast amount of information needed for the exam.
![osep_rep](/assets/img/certs/osep/osep_repo.png)
_https://github.com/GhnimiWael/OSEP_Prep_
- Repository Link: <https://github.com/GhnimiWael/OSEP_Prep>

# Conclusion
The Advanced Evasion Techniques and Breaching Defenses (PEN-300) course provides an exceptional depth of technical content across most topics, making it a valuable resource for advanced penetration testing. However, the course could benefit from an update, as new vulnerabilities and attack techniques have surfaced since its last revision, and some of the methods it covers are now less effective against modern security configurations.

Overall, the OSEP (PEN-300) course represents an expert level in penetration testing and aligns well with my focus on cybersecurity. Moving forward, I plan to deepen my specialization in this area, continuing to study and keep pace with evolving techniques and defenses in the field.

# Special Thanks

A heartfelt thank you to my colleagues, friends, and family for their guidance and support throughout this journey. I am thrilled to finally hold the OffSec Experienced Penetration Tester (OSEP) certification!

![osep_cert](/assets/img/certs/osep/osep_cert.png)
_https://www.credential.net/0799a180-0c50-474a-b048-bd7762b0db61_

- Credential: <https://www.credential.net/0799a180-0c50-474a-b048-bd7762b0db61>