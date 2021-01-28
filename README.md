# Data-scrubbing-from-mail-header-and-mail-body
Necessary features has been extracted from the email header and body. 
Scientific spam email detction is used to identify spam messages that are related to scientific articles, paper publishing, journals, conferences etc. 
To detect spam messages, certain details from email header and body has been extracted. It is done by a list of trigger keywords which was obtained from specialists of around 4500 keywords.
These keywords will parse through each email and extract those email contents in the .csv file using Java programming language.
Excel file will then be trained and tested (60% and 40% respectively) using MATLAB and Weka Neural Networks tool.
Then the results of these tools will be compared and analyzed.
