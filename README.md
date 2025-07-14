# Abastract


Gain a deeper understanding of how ransomware evades analysis and learn how to identify and counter these techniques. This workshop will explore common evasion methods, how they work, and how you can develop the skills to write code that re-enacts these methods. This workshop will begin by showing you how ransomware builders work. How do the builders generate reliable, viable ransomware code? You’ll learn! Once built, how do these malicious binaries implement analysis evasion techniques? Which techniques are used often? How do they function? We'll dive into the most prevalent techniques to show you how they work and why. Finally, you will learn how to re-enact some of these techniques along with more advanced methods within your own code. Are you ready to take your reverse engineering and coding skills to the next levels? – Let’s do this! And remember: #RansomwareSucks!


# The Outline
## Introduction (10 mins)
Welcome and Introductions
 - Overview of the workshop
 - Explain the focus: Ransomware anti-analysis/evasion techniques
 - Discuss the techniques covered
 - Explain the structure: Dissect a ransomware builder > reverse engineer a ransomware binary to find evasion techniques > write custom code to implement even more advanced evasion techniques 
 - Set ground rules and expectations (active participation, respectful environment, encouraging questions and discussion!)

## Environment Setup (20 mins)

- GitHub Lab Instructions

- Setup free accounts - Pluralsight Lab Environment

- Troubleshooting

## Part 1 Ransomware Builder Analysis (1 hr) – Ryan
- Review a ransomware builder
- What is a builder?
- How are builders used and why are they important?
- Build ransomware using the builder
- Customize the ransomware
- Build the ransomware
- Run the ransomware
- Dissect the builder using Ghidra 
- Determine how the builder uses templates to build new variants
- Review of resource sections
- Where are the templates stored?
- How are the templates decoded? What algorithm(s) are used to decode the templates 
- How do the templates eventually become stand-alone ransomware binaries?
- Extract configuration from built ransomware
- Where is the config stored in the binary?
- How is the config encoded?
- How can you decode the config in a debugger?

BREAK

## Part 2 Reverse Engineering Ransomware to Find Evasion Techniques (1 hr) – Josh
- Observing Evasion Techniques Dynamically
- Observing process behavioral patterns
- Identifying Evasion Techniques Using Static Analysis
- Identifying and Understanding Evasion Techniques
- Navigating Disassemble
- Powering-Up with the Decompiler
- Defeating Evasion
- Patching binary logic
- Adjusting analysis environment

BREAK

## [Part 3 Writing Custom Evasion Procedures (1 hr) – Aaron](./3-custom-edr-evasion/README.md) 


Conclusion (10 mins)

- Recap of the course
- Additional resources and next steps for learning
- Final Q&A and open discussion
