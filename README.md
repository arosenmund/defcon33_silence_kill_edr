# Abstract

Many cybercime and APT actors kill and/or silence EDR agents in order to evade detection, allowing them to achieve their actions on objectives without notifying security teams. How do they do it? What tools do they use? How do they write those tools? What is BYOVD? If you’re interested in learning how adversaries bypass EDR platforms, this workshop is for YOU!

Every student who attends this workshop will have a personal lab environment generated for them. Using the online lab environment, students will review a live EDR tool in order to become familiar with its capabilities, logging, and more. Students will then compile and run an EDR killer used commonly by major threat groups. Next, students will execute commands to silence agent-to-tenant communication, thereby negating notification to security teams.

Following the building, use, and analysis of readily-available tools, students will learn how to write their own code to achieve similar means. We will be using a combination of pre-provided code snippets and code we write in real-time in order to both kill and silence the provided EDR agent. Are you ready to take your reverse engineering and coding skills to the next levels? – Let’s do this! And remember: #RansomwareSucks!

# Workshop Outline

## I. Introduction (10 min) - Ryan & Aaron

1. Welcome and Introductions

2. Overview of the workshop

    1. **Our focus:** EDR killing and silencing – What’s the difference? Who uses these tactics? Why? etc.

    2. Discuss the tools & techniques covered

    3. Explain the structure:
    
        1. Compile/build readily-available tools > Run the tools > Analyze the results

        2. Write custom code to achieve similar objectives to readily-available tools > Compile the code > Run the code > Analyze the results
    
3. Set ground rules and expectations

    1. Active participation, respectful environment, questions encouraged, and discussions

## II. Environment Setup (25 min) - Aaron

**Objective:** Get lab environment set up and functional, ready for hands-on learning

1. GitHub Lab Instructions

2. Pluralsight Lab Environment: Setup free accounts

3. Ensure lab is functional

4. Troubleshooting

## III. Introduction to OpenEDR (40 min) - Ryan

**Objective:** Familiarize ourselves with our target EDR: [OpenEDR](https://www.openedr.com/)

1. What is OpenEDR? Why did we pick it for this workshop? What are some alternative FOSS EDRs?

2. How does OpenEDR operate? Where does it output logs?

3. Running some commands > Reviewing OpenEDR logs

## IV. EDR Killing via EDRSandBlast (20 min) - Ryan

**Objective:** Learn to kill EDR with readily-available EDR killer: [EDRSandBlast](https://github.com/wavestone-cdt/EDRSandblast)

    * Seen in many incidents -- e.g. ransomware cases

1. Overview of EDRSandBlast

2. Code review in Visual Studio
    
3. Building EDRSandBlast

4. Executing EDRSandblast

    1. Running commands w/EDR disabled
    
    2. Verifying executed commands **are not** logged
    
5. Disabling EDRSandBlast
    
    1. Running commands w/EDR running

    2. Verifying executed commands **are** once again logged

## V. EDR Silencing Methods (25 min) – Ryan

**Objective:** Show how to silence EDR communications

    * Silencing = Not killing the EDR, but rather silencing comms between EDR agent and logging destination/tenant

1. EDR silencing via `Add-DnsClientNrptRule`
    
2. EDR silencing via `GenericDNSServers` key
    
3. If time: EDR silencing via `PendingFileRenameOperations`

## BREAK (15 min)

## VI. Writing an EDR killer (45 min) – Aaron

**Objective:** Show how to use vulnerable drivers to implement BYOVD

1. Writing a custom EDR killer to leverage the BYOVD technique

    1. Review pre-provided code snippets

    2. Augment code live in class

    3. Compile custom code

2. Kill OpenEDR using compiled code

    1. Review results/environment
    
    2. Takeaways – Difference between using readily-available tools vs. custom code

## VII. Writing an EDR silencer (45 min) – Aaron

**Goal:** Show how to use API calls vs. living-off-the-land commands to achieve silencing

1. Writing a custom EDR silencer

    1. Review pre-provided code snippets

    2. Augment code live in class

    3. Compile custom code

2. Silence EDR using compiled code

    1. Review results/environment

    2. Takeaways – Difference between using readily-available tools <> custom code

## VIII. Wrap-up (15 min) – Aaron

1. Discussion

2. Q&A

3. Where to find Ryan & Aaron's next adventures

4. Goodbyes and farewells
