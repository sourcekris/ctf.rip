---
title: 'Interviewing in Tech: Security Engineer & Security Analyst'
date: 2024-03-07T00:00:00+00:00
author: Kris
layout: post
image: /images/2024/interviewing/koalainterview.jpeg
categories:
  - Articles
  - Security Engineering
  - Interviewing
---
Landing a job as a security engineer or analyst at a tech company is a significant feat. It requires not only technical acumen but also strong interviewing skills. This article is aimed at those seeking to navigate the interview process at tech companies. We'll cover what to expect, strategies for success, and how to make the right impression during your interviews.

![Koala Interviewing](/images/2024/interviewing/koalainterview.jpeg)

## Who am I?

I am [Kris Hunt, a Senior Staff Security Engineering Manager at Google](https://linkedin.com/in/sewid/). I've hired many folks into security engineering roles, conducted over 200 interviews for security engineers, (about 100 of those at Google). I'm also a member of Google's security engineering hiring committee for the past few years. I've spoken to a lot of students, career changers, and senior folks from industry over the years when asked about my interviewing advice and always wanted a resource to point people to. So this is it.

## Who is this article for?

This article is primarily tailored to:

- Mid-level or senior security engineers or analysts with some industry experience aiming to work for competitive tech companies.
- Recent graduates with strong security fundamentals and demonstrable projects or internships.
- Professionals from related fields (e.g., network engineering, software development) transitioning into cybersecurity.

## Interview Function
What is the function of an interview? An interview is actually a two-way street. A conversation between a candidate and a company. Let's look at it from both perspectives:

- The Company: The interviewers want to assess if you have the skills, knowledge, and problem-solving approach to address their security challenges. They're also evaluating your cultural fit– whether you share the company's values and work style.

- You, the candidate: The interview lets you determine whether the company aligns with your career goals, whether the work environment is appealing, and if the role offers appropriate challenges and opportunities. 

In order to make the most of the interview from your perspective, make sure you’re using your question time, see below where we address asking questions in interviews.

## Interview Structure

Security engineer interviews at tech companies typically involve multiple rounds:

1. Recruiter Screen: A preliminary discussion with a recruiter or HR representative to gauge your background and interest.
2. Technical Screen: A coding challenge or an interview with deeper dives into your experience with security principles, tools, and problem-solving.
3. On-site (or Virtual) Interviews: A full day of interviews covering:
   - **Coding questions**: Expect relatively simple data structures, basic algorithmic thinking, and to code in a system or document shared with your interviewer.
   - **Security Domain (DK)** and **role related knowledge (RRK)**: Specific questions on threat modeling, security protocols, incident response, and vulnerability assessment.
   - **Behavioral**: Focused on your work style, how you handle challenges, and fit with the team's culture.

# Interviewing Well
## How to Prepare

Here are some key things to be prepared with in order to ace your interview:

- **Brush Up on Fundamentals**: Review core networking concepts, cryptography, operating systems, and common web vulnerabilities.
- **Practice Coding**: Even if not a daily task at your current role, coding proficiency is expected for security engineers. 
- **Know Your Resume Inside Out**: Be prepared to speak in-depth about every project, technology, and decision you list.
- **Expect to think like an attacker and a defender**: Showcase your thought process for both identifying vulnerabilities and designing robust defenses.
- **Demonstrate Passion**: Enthusiasm for security is infectious. Let it shine through!

## Strategic Thinking in Interviews

Below are a few more strategies around formulating better interview responses I’ve used and taught to others. Remembering that an interview is not just a one way street, it's a conversation. Use that fact to your advantage.

### Clarify the Question

Questions in interviews may appear straightforward or simple, this can be the case and they might also be deceptively deep. 

If your first re-action to start answering the question then consider this approach instead. Stop and ask clarifying questions. Even if you know the answer, or if you don’t think you need clarification. I think it's a good idea to do this because:

- **It can uncover nuances or edge cases you hadn’t thought of:** The interviewer might be looking for specific aspects within the question, and clarifying helps you delve deeper and showcase a broader understanding.
- **Avoid misinterpretation:** Misinterpreting the question can lead to irrelevant or off-target answers.
- **It demonstrates your thought process**: Technical interviewers are looking for evidence of analytical thinking. What questions you ask are certainly in scope for evaluating that.
- **Clarifies your assumptions**: During the clarification process you might have made some assumptions about the scenario that are important. State those assumptions during the clarification stage to ensure you’re on the same page as the interviewer.

One of the best reasons to do this though is to **buy time**. Time allows you to think, to remember more details, to structure your answer, and to present a much more elegant solution or response to the interviewer.

## Contextualise

Every scenario exists within parameters. Within a business, an organisation or some technical structure. After clarifying the scenario with the interviewer or as part of clarifying, discuss the context of the scenario.

For example, if someone asks you to design a security control for a hypothetical situation, your first response (after clarifying questions) shouldn’t be to design the control. You should instead consider articulating the threat model you are operating within.

Who is the security control for, what sort of business? Once you have an idea of WHO you need to protect or defend then you can then think through the threat model of that business. 

A business that sells hot dogs in a physical store has a different threat model than a business who sells cyber weapons online. Talk through your threat modeling reasoning out loud so your interviewer gets insight into your ideas.

This process sets a solid foundation for your proposed solution which comes next.

## Security Domain Knowledge Fundamentals

What is meant by brushing up on fundamentals? Well you should have a broad understanding of multiple security domains. How deep your knowledge needs to be in these domains depends on how senior you are and what role you are looking to take in an organization.

The more senior a role, the deeper your knowledge needs to be across a wider number of domains. For an entry level role (graduate, intern or even L3 security engineer) not much depth is expected. For a senior security engineer (L5+) deep domain knowledge across multiple domains is going to be expected.
### Specific Study Guide

The following github repository is a good starting point for the kinds of knowledge domains you could expect to have at least some knowledge of going into a tech company security engineer or security analyst interview:

[https://github.com/gracenolan/Notes](https://github.com/gracenolan/Notes)

## Coding Questions

***Note:** Not all roles require coding, clarify with your recruiter before stressing out about coding questions!*

Security engineers at many tech companies will be expected to have coding skills coming into the role. For example security engineers in a detection role will commonly be empowered to build detection systems, encoding threat scenarios as detection rules and automate security analysis functions. Coding in these roles often allows engineers to scale themselves and amplify their impacts.

That being said, it is rarely the case that security engineers (SE) will be held to the same coding standards as professional software engineers (SWEs) during coding interviews. This section is designed to help you scope what you need to know going into an SE interview.
### Language

At the start of a coding question solution, you need to pick a language to implement your solution with. You should choose the language that you are most comfortable with. Do not choose a language that you think will impress the interviewer unless it's your most comfortable language. Your interviewer will most likely know the solution to their question across multiple languages so optimize for your own comfort.

That being said, some languages lend themselves to being used in interviews better than others. For example **Python** which works well because:

- Easy to read and compact syntax enabling shorter, faster solutions.

- Easy to use types and dynamic typing.
- Many built in methods for all of the built in types.
- Many common tools in the standard library (e.g. [itertools](https://docs.python.org/3/library/itertools.html), [collections](https://docs.python.org/3/library/collections.html), etc)

C on the other hand might have you spend much of the interview building basic functionality.
### Data structures and algorithms

In my experience, security engineering interviews limit questions to those that can be solved using these [types](https://docs.python.org/3/library/stdtypes.html):

- Strings, integers, booleans
- Arrays, lists, slices
- Hash maps (aka dictionaries, maps, hash tables)

It's good to refresh your memory about these types, how they are implemented in your preferred language and the useful built-ins that apply to them. It’s also good to know what standard library tools you could use in tricky situations.
### Questions to practice with

#### Strings

1. Is one string a palindrome of another?
2. Find all anagrams
3. Implement pattern matching regex. Support the operators . (dot) and * (star)

#### Lists

1. Remove duplicates from a list
2. Find the missing number from a list of ints
3. Rotate a matrix

#### Dictionaries

1. Count word frequencies
2. Most frequent character
3. Implement a least-recently-used LRU cache.

## Own Your Knowledge Gaps

The best candidates do not need to know everything, but can approach a solution from first principles or can build up an answer using basic components. 

If you get stumped, it's better to be honest. Start with “I don’t know” and showcase your thought process and how you'd approach finding the answer.

## Ask Questions

Inevitably, a good interviewer will stop the interview short of the meeting end time and open the floor for questions. The answer to “Do you have any questions for me?” should always be yes!

What questions to ask are completely up to you but you should use the opportunity to find out if opportunities within the company and team you’re interviewing for are aligned with your interests and career goals.

Overall there’s 3 things to remember about asking questions in interviews:

1. **Prepare the questions in advance**: Have more than one question ready and ask the one that most fits your conversation so far.
2. **Prioritise your questions**: Ask what you really want to know first.
3. **Stay positive**: Avoid taking your questions into negative territory. While there certainly are good questions that are also challenging, your question time usually comes at the end of an interview and you want to leave it on a high note.

If stuck below is a list of question ideas, but please don’t just use lists you find on the internet! Think and really focus on what’s important to you!

### What you could ask

Here’s a basic list of questions you could use but don’t limit yourself to just these. Do some reflection about what is important to you in a role:

- What does a typical day look like for a person in this role?
- What are some of the biggest challenges this team is currently facing?
- Could you give me an example of a project I might be involved in during my first few months?
- Can you describe the overall company culture and how it plays out in the day-to-day work of this team?
- What does the tech stack look like for a person in this role?
- What do you enjoy the most about working for this company?
- What led you to your current role at the company?

### What not to ask

Avoid questions that are easily answered with a bit of your own research like:

- What does the company do?
- What products do you make?

Avoid questions that the interviewer can’t answer because they wont know or they’re asked not to discuss with candidates:

- Compensation: Your interviewer isn’t likely to be the person who decides compensation and it's unlikely they will know. Ask these questions to the HR team or recruiter you have assigned.
- Did you pass the interview? Interview training generally steers interviewers away from discussing outcomes then and there. Feedback should be objective and considered and it cant take time for an interviewer to reach the conclusions they submit as feedback. This is an awkward question because they simply cannot answer you.

And avoid things of a personal or protected category nature:

- Where do you live?
- Are you married?

## Wrapping Up
Preparing for your security engineering or security analyst interview takes effort. Embrace it as a chance to showcase your skills and passion for security. Let these strategies guide your way, and remember, confidence combined with solid preparation can propel you towards success!
