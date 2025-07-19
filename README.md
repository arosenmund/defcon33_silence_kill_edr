# Abastract


Gain a deeper understanding of how ransomware evades analysis and learn how to identify and counter these techniques. This workshop will explore common evasion methods, how they work, and how you can develop the skills to write code that re-enacts these methods. This workshop will begin by showing you how ransomware builders work. How do the builders generate reliable, viable ransomware code? You’ll learn! Once built, how do these malicious binaries implement analysis evasion techniques? Which techniques are used often? How do they function? We'll dive into the most prevalent techniques to show you how they work and why. Finally, you will learn how to re-enact some of these techniques along with more advanced methods within your own code. Are you ready to take your reverse engineering and coding skills to the next levels? – Let’s do this! And remember: #RansomwareSucks!


I. Introduction (10 min) - Ryan & Aaron

A. Welcome and Introductions
B. Overview of the workshop
b1. Explain the focus: EDR killing and silencing – What’s the difference? Who uses these tactics? Why? etc.
b2. Discuss the tools & techniques covered
b3. Explain the structure: Compile/build readily-available tools > run the tools > analyze the results > write custom code to achieve same objectives > compile the code > run the code > analyze the results
C. Set ground rules and expectations (active participation, respectful environment, encouraging questions, and discussion!)

II. Environment Setup (20 min) - Aaron

A. GitHub Lab Instructions
B. Setup free accounts - Pluralsight Lab Environment
C. Troubleshooting

III. Introduction to OpenEDR (https://www.openedr.com/) (45 min) - Ryan

A. What is OpenEDR? Why did we pick it for this workshop?
B. How does OpenEDR operate? Where does it output logs?
C. Running some commands > reviewing OpenEDR logs

IV. EDR Killing & Silencing Tooling (45 min) – Ryan

A. Using EDRSandBlast (https://github.com/wavestone-cdt/EDRSandblast)
a1. Code review in Visual Studio
a2. Building EDRSandBlast
a3. Executing EDRSandblast > running new commands > verifying those commands are not logged

B. BREAK!!! (15 min)

C. Implementing EDR silencing methods
c1. EDR silencing via Add-DnsClientNrptRule (execute > analyze results)
c2. EDR silencing via GenericDNSServers key (execute > analyze results)
c3. EDR silencing via PendingFileRenameOperations (execute > analyze results)

V. Writing an EDR killer (45 min) – Aaron

A. Writing a custom EDR killing to leverage the BYOVD technique
a1. Review pre-provided code snippets
a2. Augment code live in class
a3. Goal: Show how to use vulnerable drivers to implement BYOVD
a4. Compile custom code
B. Kill OpenEDR using compiled code
b1. Review results/environment
b2. Takeaways – Difference between using readily-available tools <> custom code

C. BREAK!!! (15 min)

VI. Writing an EDR silencer (45 min) – Aaron

A. Writing a custom EDR silencer
a1. Review pre-provided code snippets
a2. Augment code live in class
a3. Goal: Show how to use API calls vs. living-off-the-land commands to achieve silencing
a4. Compile custom code
B. Silence OpenEDR using compiled code
b1. Review results/environment
b2. Takeaways – Difference between using readily-available tools <> custom code

